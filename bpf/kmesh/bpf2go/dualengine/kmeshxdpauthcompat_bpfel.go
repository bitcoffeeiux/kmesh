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

type KmeshXDPAuthCompatBpfSockTuple struct {
	Ipv4 struct {
		Saddr uint32
		Daddr uint32
		Sport uint16
		Dport uint16
	}
	_ [24]byte
}

type KmeshXDPAuthCompatBuf struct{ Data [40]int8 }

type KmeshXDPAuthCompatLogEvent struct {
	Ret uint32
	Msg [255]int8
	_   [1]byte
}

type KmeshXDPAuthCompatManagerKey struct {
	NetnsCookie uint64
	_           [8]byte
}

type KmeshXDPAuthCompatSockStorageData struct {
	ConnectNs      uint64
	Direction      uint8
	ConnectSuccess uint8
	_              [6]byte
}

// LoadKmeshXDPAuthCompat returns the embedded CollectionSpec for KmeshXDPAuthCompat.
func LoadKmeshXDPAuthCompat() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_KmeshXDPAuthCompatBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load KmeshXDPAuthCompat: %w", err)
	}

	return spec, err
}

// LoadKmeshXDPAuthCompatObjects loads KmeshXDPAuthCompat and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*KmeshXDPAuthCompatObjects
//	*KmeshXDPAuthCompatPrograms
//	*KmeshXDPAuthCompatMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadKmeshXDPAuthCompatObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadKmeshXDPAuthCompat()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// KmeshXDPAuthCompatSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshXDPAuthCompatSpecs struct {
	KmeshXDPAuthCompatProgramSpecs
	KmeshXDPAuthCompatMapSpecs
}

// KmeshXDPAuthCompatSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshXDPAuthCompatProgramSpecs struct {
	XdpShutdown *ebpf.ProgramSpec `ebpf:"xdp_shutdown"`
}

// KmeshXDPAuthCompatMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshXDPAuthCompatMapSpecs struct {
	KmeshBackend     *ebpf.MapSpec `ebpf:"kmesh_backend"`
	KmeshConfigMap   *ebpf.MapSpec `ebpf:"kmesh_config_map"`
	KmeshEndpoint    *ebpf.MapSpec `ebpf:"kmesh_endpoint"`
	KmeshEvents      *ebpf.MapSpec `ebpf:"kmesh_events"`
	KmeshFrontend    *ebpf.MapSpec `ebpf:"kmesh_frontend"`
	KmeshManage      *ebpf.MapSpec `ebpf:"kmesh_manage"`
	KmeshMap1600     *ebpf.MapSpec `ebpf:"kmesh_map1600"`
	KmeshMap192      *ebpf.MapSpec `ebpf:"kmesh_map192"`
	KmeshMap296      *ebpf.MapSpec `ebpf:"kmesh_map296"`
	KmeshMap64       *ebpf.MapSpec `ebpf:"kmesh_map64"`
	KmeshService     *ebpf.MapSpec `ebpf:"kmesh_service"`
	MapOfAuth        *ebpf.MapSpec `ebpf:"map_of_auth"`
	MapOfAuthz       *ebpf.MapSpec `ebpf:"map_of_authz"`
	MapOfSockStorage *ebpf.MapSpec `ebpf:"map_of_sock_storage"`
	MapOfTuple       *ebpf.MapSpec `ebpf:"map_of_tuple"`
	MapOfWlPolicy    *ebpf.MapSpec `ebpf:"map_of_wl_policy"`
	TmpBuf           *ebpf.MapSpec `ebpf:"tmp_buf"`
	TmpLogBuf        *ebpf.MapSpec `ebpf:"tmp_log_buf"`
}

// KmeshXDPAuthCompatObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshXDPAuthCompatObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshXDPAuthCompatObjects struct {
	KmeshXDPAuthCompatPrograms
	KmeshXDPAuthCompatMaps
}

func (o *KmeshXDPAuthCompatObjects) Close() error {
	return _KmeshXDPAuthCompatClose(
		&o.KmeshXDPAuthCompatPrograms,
		&o.KmeshXDPAuthCompatMaps,
	)
}

// KmeshXDPAuthCompatMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshXDPAuthCompatObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshXDPAuthCompatMaps struct {
	KmeshBackend     *ebpf.Map `ebpf:"kmesh_backend"`
	KmeshConfigMap   *ebpf.Map `ebpf:"kmesh_config_map"`
	KmeshEndpoint    *ebpf.Map `ebpf:"kmesh_endpoint"`
	KmeshEvents      *ebpf.Map `ebpf:"kmesh_events"`
	KmeshFrontend    *ebpf.Map `ebpf:"kmesh_frontend"`
	KmeshManage      *ebpf.Map `ebpf:"kmesh_manage"`
	KmeshMap1600     *ebpf.Map `ebpf:"kmesh_map1600"`
	KmeshMap192      *ebpf.Map `ebpf:"kmesh_map192"`
	KmeshMap296      *ebpf.Map `ebpf:"kmesh_map296"`
	KmeshMap64       *ebpf.Map `ebpf:"kmesh_map64"`
	KmeshService     *ebpf.Map `ebpf:"kmesh_service"`
	MapOfAuth        *ebpf.Map `ebpf:"map_of_auth"`
	MapOfAuthz       *ebpf.Map `ebpf:"map_of_authz"`
	MapOfSockStorage *ebpf.Map `ebpf:"map_of_sock_storage"`
	MapOfTuple       *ebpf.Map `ebpf:"map_of_tuple"`
	MapOfWlPolicy    *ebpf.Map `ebpf:"map_of_wl_policy"`
	TmpBuf           *ebpf.Map `ebpf:"tmp_buf"`
	TmpLogBuf        *ebpf.Map `ebpf:"tmp_log_buf"`
}

func (m *KmeshXDPAuthCompatMaps) Close() error {
	return _KmeshXDPAuthCompatClose(
		m.KmeshBackend,
		m.KmeshConfigMap,
		m.KmeshEndpoint,
		m.KmeshEvents,
		m.KmeshFrontend,
		m.KmeshManage,
		m.KmeshMap1600,
		m.KmeshMap192,
		m.KmeshMap296,
		m.KmeshMap64,
		m.KmeshService,
		m.MapOfAuth,
		m.MapOfAuthz,
		m.MapOfSockStorage,
		m.MapOfTuple,
		m.MapOfWlPolicy,
		m.TmpBuf,
		m.TmpLogBuf,
	)
}

// KmeshXDPAuthCompatPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshXDPAuthCompatObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshXDPAuthCompatPrograms struct {
	XdpShutdown *ebpf.Program `ebpf:"xdp_shutdown"`
}

func (p *KmeshXDPAuthCompatPrograms) Close() error {
	return _KmeshXDPAuthCompatClose(
		p.XdpShutdown,
	)
}

func _KmeshXDPAuthCompatClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed kmeshxdpauthcompat_bpfel.o
var _KmeshXDPAuthCompatBytes []byte
