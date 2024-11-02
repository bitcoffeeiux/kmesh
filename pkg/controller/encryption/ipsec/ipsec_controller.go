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
	"fmt"
	"os"
	"time"

	"istio.io/pkg/log"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	v1alpha1_core "kmesh.net/kmesh/pkg/kube/apis/kmeshnodeinfo/v1alpha1"
	informer "kmesh.net/kmesh/pkg/kube/exnodeinfo/informers/externalversions"
	v1alpha1_informers "kmesh.net/kmesh/pkg/kube/exnodeinfo/informers/externalversions/kmeshnodeinfo/v1alpha1"
	"kmesh.net/kmesh/pkg/utils"
)

const (
	MaxRetries   = 5
	ActionAdd    = "add"
	ActionDelete = "delete"
	ActionUpdate = "modify"
)

type QueueItem struct {
	name   string
	spi    int32
	nicIP  string
	bootID string
	cirds  string
	action string
}

type ipsecController struct {
	factory  informer.SharedInformerFactory
	informer v1alpha1_informers.KmeshNodeInfoInformer
	queue    workqueue.TypedRateLimitingInterface[any]
}

func NewIPsecController() (*ipsecController, error) {
	clientSet, err := utils.GetKmeshNodeInfoClient()
	if err != nil {
		err = fmt.Errorf("failed to get kmesh node info client: %v", err)
		return nil, err
	}
	factroy := informer.NewSharedInformerFactory(clientSet, time.Second*0)
	informer := factroy.Kmeshnodeinfo().V1alpha1().KmeshNodeInfos()

	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[any]())

	ipsecController := &ipsecController{
		factory:  factroy,
		informer: informer,
		queue:    queue,
	}

	if _, err := informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
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

	return ipsecController, nil
}

func (ic *ipsecController) isMine(name string) bool {
	myNodeName := os.Getenv("NODE_NAME")
	return name == myNodeName
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
		nicIP:  kni.Spec.NicIP,
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
		newKni.Spec.BootID == oldKni.Spec.BootID &&
		newKni.Spec.NicIP == oldKni.Spec.NicIP &&
		newKni.Spec.Cirds == oldKni.Spec.Cirds {
		return
	}

	ic.queue.AddRateLimited(QueueItem{name: newKni.Spec.Name,
		spi:    newKni.Spec.Spi,
		bootID: newKni.Spec.BootID,
		nicIP:  newKni.Spec.NicIP,
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
		nicIP:  kni.Spec.NicIP,
		cirds:  kni.Spec.Cirds,
		action: ActionDelete})
}

func (ic *ipsecController) Run(stop <-chan struct{}) {
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

	_, ok := key.(QueueItem)
	if !ok {
		log.Errorf("expected QueueItem but got %T", key)
		return true
	}

	ic.queue.Forget(key)

	return true
}
