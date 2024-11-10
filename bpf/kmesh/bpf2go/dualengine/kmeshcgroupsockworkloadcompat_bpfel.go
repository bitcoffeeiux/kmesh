// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package dualengine

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type KmeshCgroupSockWorkloadCompatBpfSockTuple struct {
	Ipv4 struct {
		Saddr uint32
		Daddr uint32
		Sport uint16
		Dport uint16
	}
	_ [24]byte
}

type KmeshCgroupSockWorkloadCompatBuf struct{ Data [40]int8 }

type KmeshCgroupSockWorkloadCompatLogEvent struct {
	Ret uint32
	Msg [255]int8
	_   [1]byte
}

type KmeshCgroupSockWorkloadCompatManagerKey struct {
	NetnsCookie uint64
	_           [8]byte
}

type KmeshCgroupSockWorkloadCompatOperationUsageData struct {
	StartTime     uint64
	EndTime       uint64
	PidTgid       uint64
	OperationType uint32
	_             [4]byte
}

type KmeshCgroupSockWorkloadCompatOperationUsageKey struct {
	SocketCookie  uint64
	OperationType uint32
	_             [4]byte
}

type KmeshCgroupSockWorkloadCompatSockStorageData struct {
	ConnectNs      uint64
	Direction      uint8
	ConnectSuccess uint8
	_              [6]byte
}

// LoadKmeshCgroupSockWorkloadCompat returns the embedded CollectionSpec for KmeshCgroupSockWorkloadCompat.
func LoadKmeshCgroupSockWorkloadCompat() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_KmeshCgroupSockWorkloadCompatBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load KmeshCgroupSockWorkloadCompat: %w", err)
	}

	return spec, err
}

// LoadKmeshCgroupSockWorkloadCompatObjects loads KmeshCgroupSockWorkloadCompat and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*KmeshCgroupSockWorkloadCompatObjects
//	*KmeshCgroupSockWorkloadCompatPrograms
//	*KmeshCgroupSockWorkloadCompatMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadKmeshCgroupSockWorkloadCompatObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadKmeshCgroupSockWorkloadCompat()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// KmeshCgroupSockWorkloadCompatSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshCgroupSockWorkloadCompatSpecs struct {
	KmeshCgroupSockWorkloadCompatProgramSpecs
	KmeshCgroupSockWorkloadCompatMapSpecs
}

// KmeshCgroupSockWorkloadCompatSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshCgroupSockWorkloadCompatProgramSpecs struct {
	CgroupConnect4Prog *ebpf.ProgramSpec `ebpf:"cgroup_connect4_prog"`
	CgroupConnect6Prog *ebpf.ProgramSpec `ebpf:"cgroup_connect6_prog"`
}

// KmeshCgroupSockWorkloadCompatMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshCgroupSockWorkloadCompatMapSpecs struct {
	KmeshBackend      *ebpf.MapSpec `ebpf:"kmesh_backend"`
	KmeshConfigMap    *ebpf.MapSpec `ebpf:"kmesh_config_map"`
	KmeshEndpoint     *ebpf.MapSpec `ebpf:"kmesh_endpoint"`
	KmeshEvents       *ebpf.MapSpec `ebpf:"kmesh_events"`
	KmeshFrontend     *ebpf.MapSpec `ebpf:"kmesh_frontend"`
	KmeshManage       *ebpf.MapSpec `ebpf:"kmesh_manage"`
	KmeshPerfInfo     *ebpf.MapSpec `ebpf:"kmesh_perf_info"`
	KmeshPerfMap      *ebpf.MapSpec `ebpf:"kmesh_perf_map"`
	KmeshService      *ebpf.MapSpec `ebpf:"kmesh_service"`
	Map1600           *ebpf.MapSpec `ebpf:"map1600"`
	Map192            *ebpf.MapSpec `ebpf:"map192"`
	Map296            *ebpf.MapSpec `ebpf:"map296"`
	Map64             *ebpf.MapSpec `ebpf:"map64"`
	MapOfAuth         *ebpf.MapSpec `ebpf:"map_of_auth"`
	MapOfDstInfo      *ebpf.MapSpec `ebpf:"map_of_dst_info"`
	MapOfSockStorage  *ebpf.MapSpec `ebpf:"map_of_sock_storage"`
	MapOfTailCallProg *ebpf.MapSpec `ebpf:"map_of_tail_call_prog"`
	MapOfTcpInfo      *ebpf.MapSpec `ebpf:"map_of_tcp_info"`
	MapOfTuple        *ebpf.MapSpec `ebpf:"map_of_tuple"`
	MapOfWlPolicy     *ebpf.MapSpec `ebpf:"map_of_wl_policy"`
	TmpBuf            *ebpf.MapSpec `ebpf:"tmp_buf"`
	TmpLogBuf         *ebpf.MapSpec `ebpf:"tmp_log_buf"`
}

// KmeshCgroupSockWorkloadCompatObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshCgroupSockWorkloadCompatObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshCgroupSockWorkloadCompatObjects struct {
	KmeshCgroupSockWorkloadCompatPrograms
	KmeshCgroupSockWorkloadCompatMaps
}

func (o *KmeshCgroupSockWorkloadCompatObjects) Close() error {
	return _KmeshCgroupSockWorkloadCompatClose(
		&o.KmeshCgroupSockWorkloadCompatPrograms,
		&o.KmeshCgroupSockWorkloadCompatMaps,
	)
}

// KmeshCgroupSockWorkloadCompatMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshCgroupSockWorkloadCompatObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshCgroupSockWorkloadCompatMaps struct {
	KmeshBackend      *ebpf.Map `ebpf:"kmesh_backend"`
	KmeshConfigMap    *ebpf.Map `ebpf:"kmesh_config_map"`
	KmeshEndpoint     *ebpf.Map `ebpf:"kmesh_endpoint"`
	KmeshEvents       *ebpf.Map `ebpf:"kmesh_events"`
	KmeshFrontend     *ebpf.Map `ebpf:"kmesh_frontend"`
	KmeshManage       *ebpf.Map `ebpf:"kmesh_manage"`
	KmeshPerfInfo     *ebpf.Map `ebpf:"kmesh_perf_info"`
	KmeshPerfMap      *ebpf.Map `ebpf:"kmesh_perf_map"`
	KmeshService      *ebpf.Map `ebpf:"kmesh_service"`
	Map1600           *ebpf.Map `ebpf:"map1600"`
	Map192            *ebpf.Map `ebpf:"map192"`
	Map296            *ebpf.Map `ebpf:"map296"`
	Map64             *ebpf.Map `ebpf:"map64"`
	MapOfAuth         *ebpf.Map `ebpf:"map_of_auth"`
	MapOfDstInfo      *ebpf.Map `ebpf:"map_of_dst_info"`
	MapOfSockStorage  *ebpf.Map `ebpf:"map_of_sock_storage"`
	MapOfTailCallProg *ebpf.Map `ebpf:"map_of_tail_call_prog"`
	MapOfTcpInfo      *ebpf.Map `ebpf:"map_of_tcp_info"`
	MapOfTuple        *ebpf.Map `ebpf:"map_of_tuple"`
	MapOfWlPolicy     *ebpf.Map `ebpf:"map_of_wl_policy"`
	TmpBuf            *ebpf.Map `ebpf:"tmp_buf"`
	TmpLogBuf         *ebpf.Map `ebpf:"tmp_log_buf"`
}

func (m *KmeshCgroupSockWorkloadCompatMaps) Close() error {
	return _KmeshCgroupSockWorkloadCompatClose(
		m.KmeshBackend,
		m.KmeshConfigMap,
		m.KmeshEndpoint,
		m.KmeshEvents,
		m.KmeshFrontend,
		m.KmeshManage,
		m.KmeshPerfInfo,
		m.KmeshPerfMap,
		m.KmeshService,
		m.Map1600,
		m.Map192,
		m.Map296,
		m.Map64,
		m.MapOfAuth,
		m.MapOfDstInfo,
		m.MapOfSockStorage,
		m.MapOfTailCallProg,
		m.MapOfTcpInfo,
		m.MapOfTuple,
		m.MapOfWlPolicy,
		m.TmpBuf,
		m.TmpLogBuf,
	)
}

// KmeshCgroupSockWorkloadCompatPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshCgroupSockWorkloadCompatObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshCgroupSockWorkloadCompatPrograms struct {
	CgroupConnect4Prog *ebpf.Program `ebpf:"cgroup_connect4_prog"`
	CgroupConnect6Prog *ebpf.Program `ebpf:"cgroup_connect6_prog"`
}

func (p *KmeshCgroupSockWorkloadCompatPrograms) Close() error {
	return _KmeshCgroupSockWorkloadCompatClose(
		p.CgroupConnect4Prog,
		p.CgroupConnect6Prog,
	)
}

func _KmeshCgroupSockWorkloadCompatClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed kmeshcgroupsockworkloadcompat_bpfel.o
var _KmeshCgroupSockWorkloadCompatBytes []byte
