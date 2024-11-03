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

package utils

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	kni_versioned "kmesh.net/kmesh/pkg/kube/exnodeinfo/clientset/versioned"
)

func GetK8sclient() (kubernetes.Interface, error) {
	var clientset kubernetes.Interface
	// Create the in-cluster configuration
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	// Create the Kubernetes clientset
	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return clientset, nil
}

func GetKmeshNodeInfoClient() (kni_versioned.Interface, error) {
	var clientset kni_versioned.Interface
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	// Create kmesh node info clientset
	clientset, err = kni_versioned.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}

// CreateK8sClientSet creates a Kubernetes clientset from a kubeconfig file
func CreateK8sClientSet(kubeconfig string) (kubernetes.Interface, error) {
	var clientset kubernetes.Interface
	// Build the client configuration from the kubeconfig file
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}

	// Create the Kubernetes clientset
	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}
