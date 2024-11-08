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

package workload

import (
	"fmt"
	"os"
	"reflect"
	"syscall"

	"github.com/cilium/ebpf"
	"kmesh.net/kmesh/bpf/kmesh/bpf2go"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/utils"
	"kmesh.net/kmesh/pkg/constants"
	helper "kmesh.net/kmesh/pkg/utils"
)

type BpfTCWorkload struct {
	InfoTcIngress BpfInfo
	InfoTcEgress  BpfInfo
	bpf2go.KmeshTcIngressObjects
	bpf2go.KmeshTcEgressObjects
}

func (tc *BpfTCWorkload) newBpf(info *BpfInfo, cfg *options.BpfConfig) error {
	info.MapPath = cfg.BpfFsPath + "/bpf_kmesh_workload/map/"
	info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh_workload/tc/"
	info.Cgroup2Path = cfg.Cgroup2Path

	if err := os.MkdirAll(info.MapPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	if err := os.MkdirAll(info.BpfFsPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

func (tc *BpfTCWorkload) NewBpf(cfg *options.BpfConfig) error {
	if err := tc.newBpf(&tc.InfoTcIngress, cfg); err != nil {
		return err
	}
	if err := tc.newBpf(&tc.InfoTcEgress, cfg); err != nil {
		return err
	}

	return nil
}

func (tc *BpfTCWorkload) loadKmeshTCObjects() (*ebpf.CollectionSpec, *ebpf.CollectionSpec, error) {
	var (
		errTcIngress  error
		errTcEgress   error
		specTcIngress *ebpf.CollectionSpec
		optsTcIngress ebpf.CollectionOptions
		specTcEgress  *ebpf.CollectionSpec
		optsTcEgress  ebpf.CollectionOptions
	)

	optsTcIngress.Maps.PinPath = tc.InfoTcIngress.MapPath
	optsTcEgress.Maps.PinPath = tc.InfoTcEgress.MapPath
	if helper.KernelVersionLowerThan5_13() {
		specTcIngress, errTcIngress = bpf2go.LoadKmeshTcIngressCompat()
		specTcEgress, errTcEgress = bpf2go.LoadKmeshTcEgressCompat()
	} else {
		specTcIngress, errTcIngress = bpf2go.LoadKmeshTcIngress()
		specTcEgress, errTcEgress = bpf2go.LoadKmeshTcEgress()
	}
	if errTcIngress != nil {
		return nil, nil, errTcIngress
	}
	if errTcEgress != nil {
		return nil, nil, errTcEgress
	}
	if specTcIngress == nil || specTcEgress == nil {
		return nil, nil, fmt.Errorf("error: loadKmeshTCObjects() spec is nil")
	}

	utils.SetInnerMap(specTcIngress)
	utils.SetInnerMap(specTcEgress)
	utils.SetMapPinType(specTcIngress, ebpf.PinByName)
	if err := specTcIngress.LoadAndAssign(&tc.KmeshTcIngressObjects, &optsTcIngress); err != nil {
		return nil, nil, err
	}

	if err := specTcEgress.LoadAndAssign(&tc.KmeshTcEgressObjects, &optsTcEgress); err != nil {
		return nil, nil, err
	}

	return specTcIngress, specTcEgress, nil
}

func (tc *BpfTCWorkload) LoadTC() error {
	specIngress, specEgress, err := tc.loadKmeshTCObjects()
	if err != nil {
		return err
	}

	prog := specIngress.Programs[constants.TC_INGRESS]
	tc.InfoTcIngress.Type = prog.Type
	tc.InfoTcIngress.AttachType = prog.AttachType

	prog = specEgress.Programs[constants.TC_EGRESS]
	tc.InfoTcEgress.Type = prog.Type
	tc.InfoTcEgress.AttachType = prog.AttachType

	return nil
}

func (xa *BpfTCWorkload) Close() error {
	if err := xa.KmeshTcIngressObjects.Close(); err != nil {
		return err
	}
	progVal := reflect.ValueOf(xa.KmeshTcIngressObjects.KmeshTcIngressPrograms)
	if err := utils.UnpinPrograms(&progVal); err != nil {
		return err
	}

	mapVal := reflect.ValueOf(xa.KmeshTcIngressObjects.KmeshTcIngressMaps)
	if err := utils.UnpinMaps(&mapVal); err != nil {
		return err
	}

	if err := os.RemoveAll(xa.InfoTcIngress.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if err := xa.KmeshTcEgressObjects.Close(); err != nil {
		return err
	}
	progVal = reflect.ValueOf(xa.KmeshTcEgressObjects.KmeshTcEgressPrograms)
	if err := utils.UnpinPrograms(&progVal); err != nil {
		return err
	}

	mapVal = reflect.ValueOf(xa.KmeshTcEgressObjects.KmeshTcEgressMaps)
	if err := utils.UnpinMaps(&mapVal); err != nil {
		return err
	}

	if err := os.RemoveAll(xa.InfoTcEgress.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}
