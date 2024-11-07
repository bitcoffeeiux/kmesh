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
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"istio.io/pkg/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
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
	IpSecKeyFile  = "/root/kmesh-ipsec"
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
	spi    int8
	nicIPs []string
	bootID string
	cirds  []string
	action string
}

type kmeshNodeInfo struct {
	spi    uint32
	nodeid uint16
}

type lpm_key struct {
	trie_key uint32
	ip       []uint32
}

type ipSecKeyBase struct {
	Spi         int8
	AeadKeyName string
	AeadKey     []byte
	Length      int
}

type ipSecKey struct {
	ipSecKeyBase
	ipSecLoadLock sync.RWMutex
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
	if spiload, err := strconv.Atoi(key[offsetSpi]); err != nil {
		return fmt.Errorf("ipsec config file error, invalid spi format, spi must a number, spi input is %v", key[offsetSpi])
	} else {
		is.Spi = int8(spiload)
	}
	/* spi only support 1 - 15 */
	if is.Spi < 1 || is.Spi > 15 {
		return fmt.Errorf("ipsec config file error, invalid spi range(1-15), spi input is %v", key[offsetSpi])
	}
	return nil
}

func (is *ipSecKey) GetIPSecKey() ipSecKeyBase {
	return is.ipSecKeyBase
}

func (is *ipSecKey) StartWatch(filePath string) {
	is.ipSecLoadLock.Lock()
	defer is.ipSecLoadLock.Unlock()
}

type ipsecController struct {
	factory       informer.SharedInformerFactory
	informer      v1alpha1_informers.KmeshNodeInfoInformer
	queue         workqueue.TypedRateLimitingInterface[any]
	kniClient     v1alpha1_clientset.KmeshNodeInfoInterface
	kmeshNodeInfo v1alpha1_core.KmeshNodeInfo
	ipsecKey      ipSecKey
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
		kniClient: clientSet.KmeshnodeinfoV1alpha1().KmeshNodeInfos("default"),
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

	if err = ipsecController.ipsecKey.LoadIPSecKey(IpSecKeyFile); err != nil {
		return nil, err
	}

	ipsecKeyBase := ipsecController.ipsecKey.GetIPSecKey()
	ipsecController.kmeshNodeInfo.Spec.Spi = ipsecKeyBase.Spi

	myNodeName := os.Getenv("NODE_NAME")
	myNode, err := k8sClientSet.CoreV1().Nodes().Get(context.TODO(), myNodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get kmesh node info from k8s: %v", err)
	}

	ipsecController.kmeshNodeInfo.Spec.Name = myNodeName
	ipsecController.kmeshNodeInfo.Spec.BootID = myNode.Status.NodeInfo.BootID
	ipsecController.kmeshNodeInfo.Spec.Cirds = myNode.Spec.PodCIDRs
	for _, addr := range myNode.Status.Addresses {
		if strings.Compare(string(addr.Type), "InternalIP") == 0 {
			ipsecController.kmeshNodeInfo.Spec.NicIPs = append(ipsecController.kmeshNodeInfo.Spec.NicIPs, addr.Address)
		}
	}

	// create xfrm in rule, current host not update my kmeshnodeinfo
	// the peer end does not use the key of the current host to send encrypted data.
	kmeshNodeInfoList, err := ipsecController.kniClient.List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get kmesh node info list: %v", err)
	}
	for _, node := range kmeshNodeInfoList.Items {
		if ipsecController.isMine(node.Name) {
			continue
		}
		if err = ipsecController.handleOtherNodeInfo(&node); err != nil {
			log.Errorf("failed to create xfrm rule for node %v: err: %v", node.Name, err)
		}
	}

	return ipsecController, nil
}

func (ic *ipsecController) handleOtherNodeInfo(target *v1alpha1_core.KmeshNodeInfo) error {
	/*
	 * src is remote host, dst is local host
	 * create xfrm rule like:
	 * ip xfrm state  add src {remoteNicIP} dst {localNicIP} proto esp spi 1 mode tunnel reqid 1 {aead-algo} {aead-key} {aead-key-length}
	 * ip xfrm policy add src 0.0.0.0/0     dst {localCIDR}  dir in  tmpl src {remoteNicIP} dst {localNicIP} proto esp reqid 1 mode tunnel mark 0x{remoteid}d00
	 * ip xfrm policy add src 0.0.0.0/0     dst {localCIDR}  dir fwd tmpl src {remoteNicIP} dst {localNicIP} proto esp reqid 1 mode tunnel mark 0x{remoteid}d00
	 */
	for _, remoteNicIP := range target.Spec.NicIPs {
		for _, localNicIP := range ic.kmeshNodeInfo.Spec.NicIPs {
			for _, localCIDR := range ic.kmeshNodeInfo.Spec.Cirds {
				newKey := generateIPSecKey(ic.ipsecKey.ipSecKeyBase.AeadKey, remoteNicIP, localNicIP, target.Spec.BootID, ic.kmeshNodeInfo.Spec.BootID)
				var sum utils.Sum
				sum.Write([]byte(localNicIP))
				nodeID := fmt.Sprintf("%x", sum.Sum16())
				if err := utils.InsertXfrmRule(remoteNicIP, localNicIP, nodeID, localCIDR, target.Spec.Spi, ic.ipsecKey.ipSecKeyBase.AeadKeyName,
					newKey, ic.ipsecKey.ipSecKeyBase.Length, false); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (ic *ipsecController) createXfrmOutRule(target *v1alpha1_core.KmeshNodeInfo) error {
	mapfd, err := ebpf.LoadPinnedMap(KmeshNodeInfoMapPath, nil)
	if err != nil {
		err = fmt.Errorf("failed to get kmesh node info map fd, %v", err)
		return err
	}
	/*
	 * src is local host, dst is remote host
	 * create xfrm rule like:
	 * ip xfrm state  add src {localNicIP} dst {remoteNicIP} proto esp spi 1 mode tunnel reqid 1 {aead-algo} {aead-key} {aead-key-length}
	 * ip xfrm policy add src 0.0.0.0/0    dst {remoteCIDR}  dir out tmpl src {localNicIP} dst {remoteNicIP} proto esp spi {spi} reqid 1 mode tunnel mark 0x{remoteid}e00
	 */
	for _, localNicIP := range ic.kmeshNodeInfo.Spec.NicIPs {
		for _, remoteNicIP := range target.Spec.NicIPs {
			for _, remoteCIDR := range target.Spec.Cirds {
				newKey := generateIPSecKey(ic.ipsecKey.ipSecKeyBase.AeadKey, localNicIP, remoteNicIP, ic.kmeshNodeInfo.Spec.BootID, target.Spec.BootID)
				var sum utils.Sum
				sum.Write([]byte(remoteNicIP))
				nodeID := fmt.Sprintf("%x", sum.Sum16())
				if err := utils.InsertXfrmRule(localNicIP, remoteNicIP, nodeID, remoteCIDR, target.Spec.Spi, ic.ipsecKey.ipSecKeyBase.AeadKeyName,
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
		spi:    kni.Spec.Spi,
		bootID: kni.Spec.BootID,
		nicIPs: kni.Spec.NicIPs,
		cirds:  kni.Spec.Cirds,
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
		spi:    newKni.Spec.Spi,
		bootID: newKni.Spec.BootID,
		nicIPs: newKni.Spec.NicIPs,
		cirds:  newKni.Spec.Cirds,
		action: ActionUpdate})
}

func (ic *ipsecController) handleKNIDeleteFunc(obj interface{}) {
	kni, ok := obj.(*v1alpha1_core.KmeshNodeInfo)
	if !ok {
		log.Errorf("expected *v1alpha1_core.KmeshNodeInfo but got %T in handle delete func", obj)
		return
	}
	ic.queue.AddRateLimited(QueueItem{name: kni.Spec.Name,
		spi:    kni.Spec.Spi,
		bootID: kni.Spec.BootID,
		nicIPs: kni.Spec.NicIPs,
		cirds:  kni.Spec.Cirds,
		action: ActionDelete})
}

func (ic *ipsecController) Run(stop <-chan struct{}) {
	// update my kmesh node info, notify other machines that the key can be update.
	_, err := ic.kniClient.Update(context.TODO(), &ic.kmeshNodeInfo, metav1.UpdateOptions{})
	if err != nil {
		log.Errorf("failed to update kmesh node info to k8s: %v", err)
		return
	}

	go ic.ipsecKey.StartWatch(IpSecKeyFile)

	defer ic.queue.ShutDown()
	ic.factory.Start(stop)
	if !cache.WaitForCacheSync(stop, ic.informer.Informer().HasSynced) {
		log.Error("Timed out waiting for caches to sync")
		return
	}
	for ic.processNextItem() {
	}
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

	if item.action == ActionAdd {
		kniNodeInfo, err := ic.kniClient.Get(context.TODO(), item.name, metav1.GetOptions{})
		if err != nil {
			log.Errorf("failed to get kmesh node info when process next: %v", err)
			return false
		}
		if err := ic.createXfrmOutRule(kniNodeInfo); err != nil {
			log.Errorf("create xfrm out rule failed: %v", err)
		}
	} else if item.action == ActionDelete {

	} else {

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
