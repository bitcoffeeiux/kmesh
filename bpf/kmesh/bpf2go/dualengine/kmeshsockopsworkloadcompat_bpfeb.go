// Code generated by bpf2go; DO NOT EDIT.
//go:build mips || mips64 || ppc64 || s390x

package dualengine

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type KmeshSockopsWorkloadCompatBpfSockTuple struct {
	Ipv4 struct {
		Saddr uint32
		Daddr uint32
		Sport uint16
		Dport uint16
	}
	_ [24]byte
}

type KmeshSockopsWorkloadCompatBuf struct{ Data [40]int8 }

type KmeshSockopsWorkloadCompatLogEvent struct {
	Ret uint32
	Msg [255]int8
	_   [1]byte
}

type KmeshSockopsWorkloadCompatManagerKey struct {
	NetnsCookie uint64
	_           [8]byte
}

type KmeshSockopsWorkloadCompatOperationUsageData struct {
	StartTime     uint64
	EndTime       uint64
	PidTgid       uint64
	OperationType uint32
	_             [4]byte
}

type KmeshSockopsWorkloadCompatOperationUsageKey struct {
	SocketCookie  uint64
	OperationType uint32
	_             [4]byte
}

type KmeshSockopsWorkloadCompatSockStorageData struct {
	ConnectNs      uint64
	Direction      uint8
	ConnectSuccess uint8
	_              [6]byte
}

// LoadKmeshSockopsWorkloadCompat returns the embedded CollectionSpec for KmeshSockopsWorkloadCompat.
func LoadKmeshSockopsWorkloadCompat() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_KmeshSockopsWorkloadCompatBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load KmeshSockopsWorkloadCompat: %w", err)
	}

	return spec, err
}

// LoadKmeshSockopsWorkloadCompatObjects loads KmeshSockopsWorkloadCompat and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*KmeshSockopsWorkloadCompatObjects
//	*KmeshSockopsWorkloadCompatPrograms
//	*KmeshSockopsWorkloadCompatMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadKmeshSockopsWorkloadCompatObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadKmeshSockopsWorkloadCompat()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// KmeshSockopsWorkloadCompatSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshSockopsWorkloadCompatSpecs struct {
	KmeshSockopsWorkloadCompatProgramSpecs
	KmeshSockopsWorkloadCompatMapSpecs
}

// KmeshSockopsWorkloadCompatSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshSockopsWorkloadCompatProgramSpecs struct {
	SockopsProg *ebpf.ProgramSpec `ebpf:"sockops_prog"`
}

// KmeshSockopsWorkloadCompatMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshSockopsWorkloadCompatMapSpecs struct {
	KmeshBackend     *ebpf.MapSpec `ebpf:"kmesh_backend"`
	KmeshConfigMap   *ebpf.MapSpec `ebpf:"kmesh_config_map"`
	KmeshEndpoint    *ebpf.MapSpec `ebpf:"kmesh_endpoint"`
	KmeshEvents      *ebpf.MapSpec `ebpf:"kmesh_events"`
	KmeshFrontend    *ebpf.MapSpec `ebpf:"kmesh_frontend"`
	KmeshManage      *ebpf.MapSpec `ebpf:"kmesh_manage"`
	KmeshPerfInfo    *ebpf.MapSpec `ebpf:"kmesh_perf_info"`
	KmeshPerfMap     *ebpf.MapSpec `ebpf:"kmesh_perf_map"`
	KmeshService     *ebpf.MapSpec `ebpf:"kmesh_service"`
	Map1600          *ebpf.MapSpec `ebpf:"map1600"`
	Map192           *ebpf.MapSpec `ebpf:"map192"`
	Map296           *ebpf.MapSpec `ebpf:"map296"`
	Map64            *ebpf.MapSpec `ebpf:"map64"`
	MapOfAuth        *ebpf.MapSpec `ebpf:"map_of_auth"`
	MapOfDstInfo     *ebpf.MapSpec `ebpf:"map_of_dst_info"`
	MapOfKmeshSocket *ebpf.MapSpec `ebpf:"map_of_kmesh_socket"`
	MapOfSockStorage *ebpf.MapSpec `ebpf:"map_of_sock_storage"`
	MapOfTcpInfo     *ebpf.MapSpec `ebpf:"map_of_tcp_info"`
	MapOfTuple       *ebpf.MapSpec `ebpf:"map_of_tuple"`
	MapOfWlPolicy    *ebpf.MapSpec `ebpf:"map_of_wl_policy"`
	TmpBuf           *ebpf.MapSpec `ebpf:"tmp_buf"`
	TmpLogBuf        *ebpf.MapSpec `ebpf:"tmp_log_buf"`
}

// KmeshSockopsWorkloadCompatObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshSockopsWorkloadCompatObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshSockopsWorkloadCompatObjects struct {
	KmeshSockopsWorkloadCompatPrograms
	KmeshSockopsWorkloadCompatMaps
}

func (o *KmeshSockopsWorkloadCompatObjects) Close() error {
	return _KmeshSockopsWorkloadCompatClose(
		&o.KmeshSockopsWorkloadCompatPrograms,
		&o.KmeshSockopsWorkloadCompatMaps,
	)
}

// KmeshSockopsWorkloadCompatMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshSockopsWorkloadCompatObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshSockopsWorkloadCompatMaps struct {
	KmeshBackend     *ebpf.Map `ebpf:"kmesh_backend"`
	KmeshConfigMap   *ebpf.Map `ebpf:"kmesh_config_map"`
	KmeshEndpoint    *ebpf.Map `ebpf:"kmesh_endpoint"`
	KmeshEvents      *ebpf.Map `ebpf:"kmesh_events"`
	KmeshFrontend    *ebpf.Map `ebpf:"kmesh_frontend"`
	KmeshManage      *ebpf.Map `ebpf:"kmesh_manage"`
	KmeshPerfInfo    *ebpf.Map `ebpf:"kmesh_perf_info"`
	KmeshPerfMap     *ebpf.Map `ebpf:"kmesh_perf_map"`
	KmeshService     *ebpf.Map `ebpf:"kmesh_service"`
	Map1600          *ebpf.Map `ebpf:"map1600"`
	Map192           *ebpf.Map `ebpf:"map192"`
	Map296           *ebpf.Map `ebpf:"map296"`
	Map64            *ebpf.Map `ebpf:"map64"`
	MapOfAuth        *ebpf.Map `ebpf:"map_of_auth"`
	MapOfDstInfo     *ebpf.Map `ebpf:"map_of_dst_info"`
	MapOfKmeshSocket *ebpf.Map `ebpf:"map_of_kmesh_socket"`
	MapOfSockStorage *ebpf.Map `ebpf:"map_of_sock_storage"`
	MapOfTcpInfo     *ebpf.Map `ebpf:"map_of_tcp_info"`
	MapOfTuple       *ebpf.Map `ebpf:"map_of_tuple"`
	MapOfWlPolicy    *ebpf.Map `ebpf:"map_of_wl_policy"`
	TmpBuf           *ebpf.Map `ebpf:"tmp_buf"`
	TmpLogBuf        *ebpf.Map `ebpf:"tmp_log_buf"`
}

func (m *KmeshSockopsWorkloadCompatMaps) Close() error {
	return _KmeshSockopsWorkloadCompatClose(
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
		m.MapOfKmeshSocket,
		m.MapOfSockStorage,
		m.MapOfTcpInfo,
		m.MapOfTuple,
		m.MapOfWlPolicy,
		m.TmpBuf,
		m.TmpLogBuf,
	)
}

// KmeshSockopsWorkloadCompatPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshSockopsWorkloadCompatObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshSockopsWorkloadCompatPrograms struct {
	SockopsProg *ebpf.Program `ebpf:"sockops_prog"`
}

func (p *KmeshSockopsWorkloadCompatPrograms) Close() error {
	return _KmeshSockopsWorkloadCompatClose(
		p.SockopsProg,
	)
}

func _KmeshSockopsWorkloadCompatClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed kmeshsockopsworkloadcompat_bpfeb.o
var _KmeshSockopsWorkloadCompatBytes []byte
