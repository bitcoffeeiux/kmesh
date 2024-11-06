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

package cache

import (
	"sync"

	"kmesh.net/kmesh/api/v2/workloadapi"
)

type WaypointCache interface {
	AddOrUpdateService(svc *workloadapi.Service)
	DeleteService(resourceName string)
	AddOrUpateWorkload(workload *workloadapi.Workload)
	DeleteWorkload(uid string)

	// Refresh is used to process waypoint service.
	// If it is a newly added waypoint service, it returns a series of services and workloads that need to be updated
	// whose hostname type waypoint address should be converted to IP address type. These services and workloads were
	// processed earlier but the hostname of the related waypoint could not be resolved at that time.
	Refresh(svc *workloadapi.Service) ([]*workloadapi.Service, []*workloadapi.Workload)
}

type waypointCache struct {
	mutex sync.RWMutex

	serviceCache ServiceCache

	// NOTE: The following data structure is used to change the waypoint
	// address of type hostname in the service or workload to type ip address. Because of
	// the order in which services are processed, it may be possible that corresponding
	// waypoint service can't be found when processing the service or workload. The waypoint associated
	// with a service or a workload can also changed at any time, so we need the following maps to track
	// the relationship between service & workload and its waypoint.

	// Used to track a waypoint and all services and workloads associated with it.
	// Keyed by waypoint service resource name, valued by its associated services and workloads.
	//
	// ***
	// When a service's or workload's waypoint needs to be converted, first check whether the waypoint can be found in this map.
	// If it can be found, convert it directly. Otherwise, add it to the waypointAssociatedServices and wait.
	// When the corresponding waypoint service is added to the cache, it will be processed and returned uniformly.
	// ***
	waypointAssociatedObjects map[string]*associatedObjects

	// Used to locate relevant waypoint when deleting or updating service.
	// Keyed by service resource name, valued by associated waypoint's resource name.
	serviceToWaypoint map[string]string

	// Used to locate relevant waypoint when deleting or updating workload.
	// Keyed by workload uid, valued by associated waypoint's resource name.
	workloadToWaypoint map[string]string
}

func NewWaypointCache(serviceCache ServiceCache) *waypointCache {
	return &waypointCache{
		serviceCache:              serviceCache,
		waypointAssociatedObjects: make(map[string]*associatedObjects),
		serviceToWaypoint:         make(map[string]string),
		workloadToWaypoint:        make(map[string]string),
	}
}

func (w *waypointCache) AddOrUpdateService(svc *workloadapi.Service) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	resourceName := svc.ResourceName()
	// If this is a service with an IP address type waypoint, no processing is required and
	// return directly.
	if svc.GetWaypoint() == nil || svc.GetWaypoint().GetAddress() != nil {
		// Service may become unassociated with waypoint.
		if waypoint, ok := w.serviceToWaypoint[resourceName]; ok {
			delete(w.serviceToWaypoint, resourceName)
			w.waypointAssociatedObjects[waypoint].deleteService(resourceName)
		}
		return
	}

	// If this is a svc with hostname waypoint.
	hostname := svc.GetWaypoint().GetHostname()
	waypointResourceName := hostname.GetNamespace() + "/" + hostname.GetHostname()

	if waypoint, ok := w.serviceToWaypoint[resourceName]; ok && waypoint != waypointResourceName {
		// Service updated associated waypoint, delete previous association first.
		delete(w.serviceToWaypoint, resourceName)
		w.waypointAssociatedObjects[waypoint].deleteService(resourceName)
	}

	log.Debugf("Update svc %s with waypoint %s", svc.ResourceName(), waypointResourceName)
	if associated, ok := w.waypointAssociatedObjects[waypointResourceName]; ok {
		if associated.isResolved() {
			// The waypoint corresponding to this service has been resolved.
			updateServiceWaypoint(svc, associated.waypointAddress())
		}
	} else {
		// Try to find the waypoint service from the cache.
		waypointService := w.serviceCache.GetService(waypointResourceName)
		var addr *workloadapi.NetworkAddress
		if waypointService != nil && len(waypointService.GetAddresses()) != 0 {
			addr = waypointService.GetAddresses()[0]
			updateServiceWaypoint(svc, waypointService.GetAddresses()[0])
		}
		w.waypointAssociatedObjects[waypointResourceName] = newAssociatedObjects(addr)
	}
	w.serviceToWaypoint[resourceName] = waypointResourceName
	// Anyway, add svc to the association list.
	w.waypointAssociatedObjects[waypointResourceName].addService(resourceName, svc)
}

func (w *waypointCache) DeleteService(resourceName string) {
	// This service has waypoint.
	if waypoint, ok := w.serviceToWaypoint[resourceName]; ok {
		delete(w.serviceToWaypoint, resourceName)
		w.waypointAssociatedObjects[waypoint].deleteService(resourceName)
	}

	// This may be a waypoint service.
	delete(w.waypointAssociatedObjects, resourceName)
}

func (w *waypointCache) AddOrUpateWorkload(workload *workloadapi.Workload) {

}

func (w *waypointCache) DeleteWorkload(uid string) {

}

func (w *waypointCache) Refresh(svc *workloadapi.Service) ([]*workloadapi.Service, []*workloadapi.Workload) {
	if len(svc.GetAddresses()) == 0 {
		return nil, nil
	}

	address := svc.GetAddresses()[0]
	resourceName := svc.ResourceName()

	w.mutex.Lock()
	defer w.mutex.Unlock()

	// If this svc is a waypoint service, may need refreshing.
	if associated, ok := w.waypointAssociatedObjects[resourceName]; ok {
		waypointAddr := associated.waypointAddress()
		if waypointAddr != nil && waypointAddr.String() == address.String() {
			return nil, nil
		}

		log.Debugf("Refreshing services associated with waypoint %s", resourceName)
		return associated.update(address)
	}

	return nil, nil
}

type associatedObjects struct {
	mutex sync.RWMutex
	// IP address of waypoint.
	// If it is nil, it means that the waypoint service has not been processed yet.
	address *workloadapi.NetworkAddress

	// Associated services of this waypoint.
	// The key of this map is service resource name and value is corresponding service structure.
	services map[string]*workloadapi.Service

	// Associated workloads of this waypoint.
	// The key of this map is workload uid and value is corresponding workload structure.
	workloads map[string]*workloadapi.Workload
}

func newAssociatedObjects(addr *workloadapi.NetworkAddress) *associatedObjects {
	return &associatedObjects{
		address:   addr,
		services:  make(map[string]*workloadapi.Service),
		workloads: make(map[string]*workloadapi.Workload),
	}
}

func (w *associatedObjects) isResolved() bool {
	return w.address != nil
}

func (w *associatedObjects) waypointAddress() *workloadapi.NetworkAddress {
	return w.address
}

func (w *associatedObjects) update(addr *workloadapi.NetworkAddress) ([]*workloadapi.Service, []*workloadapi.Workload) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	w.address = addr

	svcs := []*workloadapi.Service{}
	workloads := []*workloadapi.Workload{}

	for _, svc := range w.services {
		updateServiceWaypoint(svc, addr)
		svcs = append(svcs, svc)
	}

	for _, workload := range w.workloads {
		updateWorkloadWaypoint(workload, addr)
		workloads = append(workloads, workload)
	}

	return svcs, workloads
}

func (w *associatedObjects) addService(resourceName string, service *workloadapi.Service) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	w.services[resourceName] = service
}

func (w *associatedObjects) deleteService(resourceName string) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	delete(w.services, resourceName)
}

func (w *associatedObjects) addWorkload(uid string, workload *workloadapi.Workload) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	w.workloads[uid] = workload
}

func (w *associatedObjects) deleteWorkload(uid string) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	delete(w.workloads, uid)
}

func updateServiceWaypoint(svc *workloadapi.Service, addr *workloadapi.NetworkAddress) {
	svc.GetWaypoint().Destination = &workloadapi.GatewayAddress_Address{
		Address: addr,
	}
}

func updateWorkloadWaypoint(workload *workloadapi.Workload, addr *workloadapi.NetworkAddress) {
	workload.GetWaypoint().Destination = &workloadapi.GatewayAddress_Address{
		Address: addr,
	}
}
