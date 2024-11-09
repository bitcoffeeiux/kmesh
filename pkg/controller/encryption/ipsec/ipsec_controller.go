/*
 * Copyright The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ipsec

import (
	"bufio"
	"context"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"istio.io/istio/pkg/filewatcher"

	"github.com/cilium/ebpf"
	netns "github.com/containernetworking/plugins/pkg/ns"
	"github.com/fsnotify/fsnotify"
	"github.com/vishvananda/netlink"
	"istio.io/pkg/log"
	v1 "k8s.io/api/core/v1"
	api_errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"kmesh.net/kmesh/pkg/constants"
	kmesh_netns "kmesh.net/kmesh/pkg/controller/netns"
	v1alpha1_core "kmesh.net/kmesh/pkg/kube/apis/kmeshnodeinfo/v1alpha1"
	v1alpha1_clientset "kmesh.net/kmesh/pkg/kube/exnodeinfo/clientset/versioned/typed/kmeshnodeinfo/v1alpha1"
	informer "kmesh.net/kmesh/pkg/kube/exnodeinfo/informers/externalversions"
	v1alpha1_informers "kmesh.net/kmesh/pkg/kube/exnodeinfo/informers/externalversions/kmeshnodeinfo/v1alpha1"
	"kmesh.net/kmesh/pkg/utils"
)

const (
	MaxRetries    = 5
	ActionAdd     = "add"
	ActionDelete  = "delete"
	ActionUpdate  = "modify"
	IpSecKeyFile  = "/root/kmesh-ipsec/keys"
	offsetSpi     = 0
	offsetAead    = 1
	offsetAeadKey = 2
	offsetAeadLen = 3
)

const (
	KmeshNodeInfoMapPath = "/sys/fs/bpf/bpf_kmesh_workload/map/map_of_nodeinfo"
)

type QueueItem struct {
	name   string
	action string
}

type kmeshNodeInfo struct {
	spi    uint32
	nodeid uint16
	_      uint16
}

type lpm_key struct {
	trie_key uint32
	ip       [4]uint32
}

type ipSecKeyBase struct {
	Spi         int8
	OldSpi      int8
	AeadKeyName string
	AeadKey     []byte
	Length      int
}

type ipSecKey struct {
	ipSecKeyBase
	ipSecLoadLock sync.RWMutex
	watcher       filewatcher.FileWatcher
}

func (is *ipSecKey) LoadIPSecKey(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("load ipsec keys failed: %v", err)
	}
	defer file.Close()

	is.ipSecLoadLock.Lock()
	defer is.ipSecLoadLock.Unlock()

	// [spi] aead-algo aead-keyLine icv-len
	// only tail line effect
	err = is.loadIPSecKeyFromIO(file)
	if err != nil {
		return err
	}
	return nil
}

func (is *ipSecKey) loadIPSecKeyFromIO(file *os.File) error {
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {

		keyLine := strings.Split(scanner.Text(), " ")
		if len(keyLine) != 4 {
			return fmt.Errorf("ipsec config file error, invalid format, need aead algo")
		}
		err := is.parserSpi(keyLine)
		if err != nil {
			return err
		}
		err = is.parserAeadKey(keyLine)
		if err != nil {
			return err
		}
	}
	return nil
}

func (is *ipSecKey) parserAeadKey(keyLine []string) error {
	if !strings.HasPrefix(keyLine[offsetAead], "rfc") {
		return fmt.Errorf("ipsec config file error, invalid algo name, aead need begin with \"rfc\"")
	}
	is.AeadKeyName = keyLine[offsetAead]
	baseKeyTrim := strings.TrimPrefix(keyLine[offsetAeadKey], "0x")
	if key, err := hex.DecodeString(baseKeyTrim); err != nil {
		return fmt.Errorf("ipsec config file error, aead key decode failed, err is %v", err)
	} else {
		is.AeadKey = key
	}

	if length, err := strconv.Atoi(keyLine[offsetAeadLen]); err != nil {
		return fmt.Errorf("ipsec config file error, aead key length invalid, err is %v", err)
	} else {
		is.Length = length
	}
	return nil
}

func (is *ipSecKey) parserSpi(key []string) error {
	spiload, err := strconv.Atoi(key[offsetSpi])
	if err != nil {
		return fmt.Errorf("ipsec config file error, invalid spi format, spi must a number, spi input is %v", key[offsetSpi])
	}

	if is.Spi != 0 {
		is.OldSpi = is.Spi
	}

	is.Spi = int8(spiload)
	/* spi only support 1 - 15 */
	if is.Spi < 1 || is.Spi > 15 {
		return fmt.Errorf("ipsec config file error, invalid spi range(1-15), spi input is %v", key[offsetSpi])
	}
	return nil
}

func (is *ipSecKey) GetIPSecKey() ipSecKeyBase {
	return is.ipSecKeyBase
}

func (is *ipSecKey) StartWatch(updateChain chan bool) error {
	is.watcher = filewatcher.NewWatcher()

	if err := is.watcher.Add(IpSecKeyFile); err != nil {
		return fmt.Errorf("failed to add %s to file watcher: %v", IpSecKeyFile, err)
	}
	go func() {
		log.Infof("start watching file %s", IpSecKeyFile)

		var timerC <-chan time.Time
		for {
			select {
			case <-timerC:
				timerC = nil
				if err := is.LoadIPSecKey(IpSecKeyFile); err != nil {
					log.Errorf("failed to update ipsec, %v", err)
					continue
				}
				updateChain <- true

			case event := <-is.watcher.Events(IpSecKeyFile):
				log.Debugf("got event %s", event.String())

				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					if timerC == nil {
						timerC = time.After(100 * time.Millisecond)
					}
				}
			case err := <-is.watcher.Errors(IpSecKeyFile):
				if err != nil {
					log.Errorf("err from errors channel of file watcher: %v", err)
					return
				}
			}
		}
	}()
	return nil
}

type ipsecController struct {
	factory       informer.SharedInformerFactory
	informer      v1alpha1_informers.KmeshNodeInfoInformer
	queue         workqueue.TypedRateLimitingInterface[any]
	kniClient     v1alpha1_clientset.KmeshNodeInfoInterface
	kmeshNodeInfo v1alpha1_core.KmeshNodeInfo
	ipsecKey      ipSecKey
	myNode        *v1.Node
}

func NewIPsecController(k8sClientSet kubernetes.Interface) (*ipsecController, error) {
	clientSet, err := utils.GetKmeshNodeInfoClient()
	if err != nil {
		err = fmt.Errorf("failed to get kmesh node info client: %v", err)
		return nil, err
	}
	factroy := informer.NewSharedInformerFactory(clientSet, time.Second*0)

	ipsecController := &ipsecController{
		factory:   factroy,
		informer:  factroy.Kmeshnodeinfo().V1alpha1().KmeshNodeInfos(),
		queue:     workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[any]()),
		kniClient: clientSet.KmeshnodeinfoV1alpha1().KmeshNodeInfos("kmesh-system"),
	}

	if _, err := ipsecController.informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ipsecController.handleKNIAddFunc(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			ipsecController.handleKNIUpdateFunc(oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			ipsecController.handleKNIDeleteFunc(obj)
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to add event handler to kmeshnodeinfoInformer: %v", err)
	}

	myNodeName := os.Getenv("NODE_NAME")
	myNode, err := k8sClientSet.CoreV1().Nodes().Get(context.TODO(), myNodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get kmesh node info from k8s: %v", err)
	}
	ipsecController.myNode = myNode
	return ipsecController, nil
}

func (ic *ipsecController) handleOtherNodeInfo(target *v1alpha1_core.KmeshNodeInfo) error {
	nodeNsPath, err := kmesh_netns.GetNodeNSpath(ic.myNode)
	if err != nil {
		err = fmt.Errorf("failed to get current node ns path")
		return err
	}
	mapfd, err := ebpf.LoadPinnedMap(KmeshNodeInfoMapPath, nil)
	if err != nil {
		err = fmt.Errorf("failed to get kmesh node info map fd, %v", err)
		return err
	}
	/*
	 * src is remote host, dst is local host
	 * create xfrm rule like:
	 * ip xfrm state  add src {remoteNicIP} dst {localNicIP} proto esp spi 1 mode tunnel reqid 1 {aead-algo} {aead-key} {aead-key-length}
	 * ip xfrm policy add src 0.0.0.0/0     dst {localCIDR}  dir in  tmpl src {remoteNicIP} dst {localNicIP} proto esp reqid 1 mode tunnel mark 0x{remoteid}d00
	 * ip xfrm policy add src 0.0.0.0/0     dst {localCIDR}  dir fwd tmpl src {remoteNicIP} dst {localNicIP} proto esp reqid 1 mode tunnel mark 0x{remoteid}d00
	 */
	handleInXfrm := func(netns.NetNS) error {
		for _, remoteNicIP := range target.Spec.NicIPs {
			for _, localNicIP := range ic.kmeshNodeInfo.Spec.NicIPs {
				for _, localCIDR := range ic.kmeshNodeInfo.Spec.Cirds {
					newKey := generateIPSecKey(ic.ipsecKey.ipSecKeyBase.AeadKey, remoteNicIP, localNicIP, target.Spec.BootID, ic.kmeshNodeInfo.Spec.BootID)
					var sum utils.Sum
					sum.Write([]byte(localNicIP))
					nodeID := fmt.Sprintf("%x", sum.Sum16())

					if err := utils.InsertXfrmRule(remoteNicIP, localNicIP, localCIDR, nodeID, target.Spec.Spi, ic.ipsecKey.ipSecKeyBase.AeadKeyName,
						newKey, ic.ipsecKey.ipSecKeyBase.Length, false); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if err := netns.WithNetNSPath(nodeNsPath, handleInXfrm); err != nil {
		return err
	}
	/*
	 * src is local host, dst is remote host
	 * create xfrm rule like:
	 * ip xfrm state  add src {localNicIP} dst {remoteNicIP} proto esp spi 1 mode tunnel reqid 1 {aead-algo} {aead-key} {aead-key-length}
	 * ip xfrm policy add src 0.0.0.0/0    dst {remoteCIDR}  dir out tmpl src {localNicIP} dst {remoteNicIP} proto esp spi {spi} reqid 1 mode tunnel mark 0x{remoteid}e00
	 */
	handleOutXfrm := func(netns.NetNS) error {
		for _, localNicIP := range ic.kmeshNodeInfo.Spec.NicIPs {
			for _, remoteNicIP := range target.Spec.NicIPs {
				for _, remoteCIDR := range target.Spec.Cirds {
					newKey := generateIPSecKey(ic.ipsecKey.ipSecKeyBase.AeadKey, localNicIP, remoteNicIP, ic.kmeshNodeInfo.Spec.BootID, target.Spec.BootID)
					var sum utils.Sum
					sum.Write([]byte(remoteNicIP))
					nodeID := fmt.Sprintf("%x", sum.Sum16())
					if err := utils.InsertXfrmRule(localNicIP, remoteNicIP, remoteCIDR, nodeID, target.Spec.Spi, ic.ipsecKey.ipSecKeyBase.AeadKeyName,
						newKey, ic.ipsecKey.ipSecKeyBase.Length, true); err != nil {
						return err
					}
					cidr := strings.Split(remoteCIDR, "/")
					prefix, _ := strconv.Atoi(cidr[1])
					kniKey := lpm_key{
						trie_key: uint32(prefix),
					}
					ip, _ := netip.ParseAddr(cidr[0])
					if ip.Is4() {
						kniKey.ip[0] = binary.BigEndian.Uint32(ip.AsSlice())
					} else if ip.Is6() {
						// TODO
					}

					kniValue := kmeshNodeInfo{
						spi:    uint32(ic.ipsecKey.Spi),
						nodeid: sum.Sum16(),
					}

					if err := mapfd.Update(&kniKey, &kniValue, ebpf.UpdateAny); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if err := netns.WithNetNSPath(nodeNsPath, handleOutXfrm); err != nil {
		return err
	}

	return nil
}

func (ic *ipsecController) isMine(name string) bool {
	myNodeName := os.Getenv("NODE_NAME")
	return strings.Compare(name, myNodeName) == 0
}

func (ic *ipsecController) handleKNIAddFunc(obj interface{}) {
	kni, ok := obj.(*v1alpha1_core.KmeshNodeInfo)
	if !ok {
		log.Errorf("expected *v1alpha1_core.KmeshNodeInfo but got %T in handle add func", obj)
		return
	}

	if ic.isMine(kni.Spec.Name) {
		return
	}

	ic.queue.AddRateLimited(QueueItem{name: kni.Spec.Name,
		action: ActionAdd})
}

func (ic *ipsecController) handleKNIUpdateFunc(_, newObj interface{}) {
	newKni, okNew := newObj.(*v1alpha1_core.KmeshNodeInfo)
	if !okNew {
		log.Errorf("expected *v1alpha1_core.KmeshNodeInfo but got %T in handle update new obj func", newObj)
		return
	}

	oldKni, okold := newObj.(*v1alpha1_core.KmeshNodeInfo)
	if !okold {
		log.Errorf("expected *v1alpha1_core.KmeshNodeInfo but got %T in handle update old obj func", newObj)
		return
	}

	if ic.isMine(newKni.Spec.Name) {
		return
	}

	if newKni.Spec.Name == oldKni.Spec.Name &&
		newKni.Spec.Spi == oldKni.Spec.Spi &&
		newKni.Spec.BootID == oldKni.Spec.BootID {
		return
	}

	ic.queue.AddRateLimited(QueueItem{name: newKni.Spec.Name,
		action: ActionUpdate})
}

func (ic *ipsecController) handleKNIDeleteFunc(obj interface{}) {
	kni, ok := obj.(*v1alpha1_core.KmeshNodeInfo)
	if !ok {
		log.Errorf("expected *v1alpha1_core.KmeshNodeInfo but got %T in handle delete func", obj)
		return
	}
	ic.queue.AddRateLimited(QueueItem{name: kni.Spec.Name,
		action: ActionDelete})
}

func (ic *ipsecController) Run(stop <-chan struct{}) {
	err := ic.ipsecKey.LoadIPSecKey(IpSecKeyFile)
	if err != nil {
		log.Errorf(err)
		return
	}

	ipsecKeyBase := ic.ipsecKey.GetIPSecKey()
	ic.kmeshNodeInfo.Spec.Spi = ipsecKeyBase.Spi

	myNodeName := os.Getenv("NODE_NAME")

	ic.kmeshNodeInfo.Name = myNodeName
	ic.kmeshNodeInfo.Spec.Name = myNodeName
	ic.kmeshNodeInfo.Spec.BootID = ic.myNode.Status.NodeInfo.BootID
	ic.kmeshNodeInfo.Spec.Cirds = ic.myNode.Spec.PodCIDRs

	for _, addr := range ic.myNode.Status.Addresses {
		if strings.Compare(string(addr.Type), "InternalIP") == 0 {
			ic.kmeshNodeInfo.Spec.NicIPs = append(ic.kmeshNodeInfo.Spec.NicIPs, addr.Address)
		}
	}

	ok := ic.attachTCforInternalNic()
	if !ok {
		return
	}

	// create xfrm in rule, current host not update my kmeshnodeinfo
	// the peer end does not use the key of the current host to send encrypted data.
	ok = ic.handleAllKmeshNodeInfo()
	if !ok {
		return
	}
	// update my kmesh node info, notify other machines that the key can be update.
	ok = ic.updateKmeshNodeInfo(err)
	if !ok {
		return
	}
	ipsecUpdateChan := make(chan bool)
	ic.ipsecKey.StartWatch(ipsecUpdateChan)

	go func() {
		nodeNsPath, err := kmesh_netns.GetNodeNSpath(ic.myNode)
		if err != nil {
			log.Errorf("failed to get nodens path, %v", err)
			return
		}
		for {
			select {
			case <-ipsecUpdateChan:

				updateXfrm := func(netns.NetNS) error {
					if err := utils.CreateNewStateFromOldByLocalNidIP(ic.ipsecKey.Spi, ic.ipsecKey.OldSpi, ic.kmeshNodeInfo.Spec.NicIPs); err != nil {
						log.Errorf("failed to CreateNewState, %v", err)
					}
					return nil
				}
				if err := netns.WithNetNSPath(nodeNsPath, updateXfrm); err != nil {
					continue
				}

				tmpUpdate, err := ic.kniClient.Get(context.TODO(), ic.kmeshNodeInfo.Name, metav1.GetOptions{})
				if err != nil {
					log.Errorf("failed to get kmesh node info to k8s: %v", err)
					continue
				}
				ic.kmeshNodeInfo.ResourceVersion = tmpUpdate.ResourceVersion
				ic.kmeshNodeInfo.Spec.Spi = ic.ipsecKey.Spi
				_, err = ic.kniClient.Update(context.TODO(), &ic.kmeshNodeInfo, metav1.UpdateOptions{})
				if err != nil {
					log.Errorf("failed to update kmeshinfo, %v", err)
					continue
				}
			case <-time.After(time.Second):
				continue
			}
		}
	}()

	defer ic.queue.ShutDown()
	ic.factory.Start(stop)
	if !cache.WaitForCacheSync(stop, ic.informer.Informer().HasSynced) {
		log.Error("Timed out waiting for caches to sync")
		return
	}
	for ic.processNextItem() {
	}
}

func (ic *ipsecController) handleAllKmeshNodeInfo() bool {
	kmeshNodeInfoList, err := ic.kniClient.List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("failed to get kmesh node info list: %v", err)
		return false
	}
	for _, node := range kmeshNodeInfoList.Items {
		if ic.isMine(node.Name) {
			continue
		}
		if err = ic.handleOtherNodeInfo(&node); err != nil {
			log.Errorf("failed to create xfrm rule for node %v: err: %v", node.Name, err)
		}
	}
	return true
}

func (ic *ipsecController) updateKmeshNodeInfo(err error) bool {
	_, err = ic.kniClient.Create(context.TODO(), &ic.kmeshNodeInfo, metav1.CreateOptions{})
	if err != nil && !api_errors.IsAlreadyExists(err) {
		log.Errorf("failed to create kmesh node info to k8s: %v", err)
		return false
	}
	tmpUpdate, err := ic.kniClient.Get(context.TODO(), ic.kmeshNodeInfo.Name, metav1.GetOptions{})
	if err != nil {
		log.Errorf("failed to get kmesh node info to k8s: %v", err)
		return false
	}
	ic.kmeshNodeInfo.ResourceVersion = tmpUpdate.ResourceVersion
	_, err = ic.kniClient.Update(context.TODO(), &ic.kmeshNodeInfo, metav1.UpdateOptions{})
	if err != nil {
		log.Errorf("failed to update kmeshinfo, %v", err)
		return false
	}
	return true
}

func (ic *ipsecController) attachTCforInternalNic() bool {
	tc, err := utils.GetProgramByName(constants.TC_INGRESS)
	if err != nil {
		log.Errorf("failed to get tc ebpf program in ipsec controller, %v", err)
		return false
	}

	nicInterfaces, err := net.Interfaces()
	if err != nil {
		log.Errorf("failed to get interfaces: %v", err)
		return false
	}

	for _, targetAddrString := range ic.kmeshNodeInfo.Spec.NicIPs {
		targetAddr := net.ParseIP(targetAddrString)
		for _, iface := range nicInterfaces {
			ifAddrs, err := iface.Addrs()
			if err != nil {
				log.Warnf("failed to convert interface %v, %v", iface, err)
				continue
			}
			link, err := netlink.LinkByName(iface.Name)
			if err != nil {
				log.Warnf("failed to link interface %v, %v", iface, err)
				continue
			}

			for _, ifaddr := range ifAddrs {
				ipNet, ok := ifaddr.(*net.IPNet)
				if !ok {
					log.Warnf("failed to convert ifaddr %v, %v", ifaddr, err)
					continue
				}
				if ipNet.IP.Equal(targetAddr) {
					err = utils.AttchTCProgram(link, tc, utils.TC_DIR_INGRESS)
					if err != nil {
						log.Warnf("failed to attach tc ebpf on interface %v, %v", iface, err)
						continue
					}
				}
			}
		}
	}
	return true
}

func (ic *ipsecController) processNextItem() bool {
	key, quit := ic.queue.Get()
	if quit {
		return false
	}
	defer ic.queue.Done(key)

	item, ok := key.(QueueItem)
	if !ok {
		log.Errorf("expected QueueItem but got %T", key)
		return true
	}

	if item.action == ActionAdd || item.action == ActionUpdate {
		kniNodeInfo, err := ic.kniClient.Get(context.TODO(), item.name, metav1.GetOptions{})
		if err != nil {
			log.Errorf("failed to get kmesh node info when process next: %v", err)
			return false
		}
		if err := ic.handleOtherNodeInfo(kniNodeInfo); err != nil {
			log.Errorf("create xfrm out rule failed in processNextItem for node %v: %v", kniNodeInfo.Name, err)
		}
	}

	ic.queue.Forget(key)

	return true
}

func generateIPSecKey(baseKey []byte, srcIP, dstIP, srcBootID, dstBootID string) []byte {
	inputLen := len(baseKey) + len(srcIP) + len(dstIP) + len(srcBootID) + len(dstBootID)
	input := make([]byte, 0, inputLen)
	input = append(input, baseKey...)
	input = append(input, []byte(srcIP)...)
	input = append(input, []byte(dstIP)...)
	input = append(input, []byte(srcBootID)[:36]...)
	input = append(input, []byte(dstBootID)[:36]...)

	hash := sha512.Sum512(input)
	return hash[:len(baseKey)]
}
