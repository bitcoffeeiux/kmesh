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
// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	context "context"
	time "time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
	apiskmeshnodeinfov1alpha1 "kmesh.net/kmesh/pkg/kube/apis/kmeshnodeinfo/v1alpha1"
	versioned "kmesh.net/kmesh/pkg/kube/exnodeinfo/clientset/versioned"
	internalinterfaces "kmesh.net/kmesh/pkg/kube/exnodeinfo/informers/externalversions/internalinterfaces"
	kmeshnodeinfov1alpha1 "kmesh.net/kmesh/pkg/kube/exnodeinfo/listers/kmeshnodeinfo/v1alpha1"
)

// KmeshNodeInfoInformer provides access to a shared informer and lister for
// KmeshNodeInfos.
type KmeshNodeInfoInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() kmeshnodeinfov1alpha1.KmeshNodeInfoLister
}

type kmeshNodeInfoInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewKmeshNodeInfoInformer constructs a new informer for KmeshNodeInfo type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewKmeshNodeInfoInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredKmeshNodeInfoInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredKmeshNodeInfoInformer constructs a new informer for KmeshNodeInfo type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredKmeshNodeInfoInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.KmeshnodeinfoV1alpha1().KmeshNodeInfos(namespace).List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.KmeshnodeinfoV1alpha1().KmeshNodeInfos(namespace).Watch(context.TODO(), options)
			},
		},
		&apiskmeshnodeinfov1alpha1.KmeshNodeInfo{},
		resyncPeriod,
		indexers,
	)
}

func (f *kmeshNodeInfoInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredKmeshNodeInfoInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *kmeshNodeInfoInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&apiskmeshnodeinfov1alpha1.KmeshNodeInfo{}, f.defaultInformer)
}

func (f *kmeshNodeInfoInformer) Lister() kmeshnodeinfov1alpha1.KmeshNodeInfoLister {
	return kmeshnodeinfov1alpha1.NewKmeshNodeInfoLister(f.Informer().GetIndexer())
}
