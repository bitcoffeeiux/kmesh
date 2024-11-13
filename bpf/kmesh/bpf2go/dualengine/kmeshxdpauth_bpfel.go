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

type KmeshXDPAuthBpfSockTuple struct {
	Ipv4 struct {
		Saddr uint32
		Daddr uint32
		Sport uint16
		Dport uint16
	}
	_ [24]byte
}

type KmeshXDPAuthBuf struct{ Data [40]int8 }

type KmeshXDPAuthKmeshConfig struct {
	BpfLogLevel uint32
	NodeIp      [4]uint32
	PodGateway  [4]uint32
}

type KmeshXDPAuthLogEvent struct {
	Ret uint32
	Msg [255]int8
	_   [1]byte
}

type KmeshXDPAuthManagerKey struct {
	NetnsCookie uint64
	_           [8]byte
}

type KmeshXDPAuthSockStorageData struct {
	ConnectNs      uint64
	Direction      uint8
	ConnectSuccess uint8
	_              [6]byte
}

// LoadKmeshXDPAuth returns the embedded CollectionSpec for KmeshXDPAuth.
func LoadKmeshXDPAuth() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_KmeshXDPAuthBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load KmeshXDPAuth: %w", err)
	}

	return spec, err
}

// LoadKmeshXDPAuthObjects loads KmeshXDPAuth and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*KmeshXDPAuthObjects
//	*KmeshXDPAuthPrograms
//	*KmeshXDPAuthMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadKmeshXDPAuthObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadKmeshXDPAuth()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// KmeshXDPAuthSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshXDPAuthSpecs struct {
	KmeshXDPAuthProgramSpecs
	KmeshXDPAuthMapSpecs
}

// KmeshXDPAuthSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshXDPAuthProgramSpecs struct {
	XdpShutdown *ebpf.ProgramSpec `ebpf:"xdp_shutdown"`
}

// KmeshXDPAuthMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshXDPAuthMapSpecs struct {
	InnerMap         *ebpf.MapSpec `ebpf:"inner_map"`
	KmeshBackend     *ebpf.MapSpec `ebpf:"kmesh_backend"`
	KmeshConfigMap   *ebpf.MapSpec `ebpf:"kmesh_config_map"`
	KmeshEndpoint    *ebpf.MapSpec `ebpf:"kmesh_endpoint"`
	KmeshEvents      *ebpf.MapSpec `ebpf:"kmesh_events"`
	KmeshFrontend    *ebpf.MapSpec `ebpf:"kmesh_frontend"`
	KmeshManage      *ebpf.MapSpec `ebpf:"kmesh_manage"`
	KmeshService     *ebpf.MapSpec `ebpf:"kmesh_service"`
	MapOfAuth        *ebpf.MapSpec `ebpf:"map_of_auth"`
	MapOfAuthz       *ebpf.MapSpec `ebpf:"map_of_authz"`
	MapOfSockStorage *ebpf.MapSpec `ebpf:"map_of_sock_storage"`
	MapOfTuple       *ebpf.MapSpec `ebpf:"map_of_tuple"`
	MapOfWlPolicy    *ebpf.MapSpec `ebpf:"map_of_wl_policy"`
	OuterMap         *ebpf.MapSpec `ebpf:"outer_map"`
	TmpBuf           *ebpf.MapSpec `ebpf:"tmp_buf"`
	TmpLogBuf        *ebpf.MapSpec `ebpf:"tmp_log_buf"`
}

// KmeshXDPAuthObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshXDPAuthObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshXDPAuthObjects struct {
	KmeshXDPAuthPrograms
	KmeshXDPAuthMaps
}

func (o *KmeshXDPAuthObjects) Close() error {
	return _KmeshXDPAuthClose(
		&o.KmeshXDPAuthPrograms,
		&o.KmeshXDPAuthMaps,
	)
}

// KmeshXDPAuthMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshXDPAuthObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshXDPAuthMaps struct {
	InnerMap         *ebpf.Map `ebpf:"inner_map"`
	KmeshBackend     *ebpf.Map `ebpf:"kmesh_backend"`
	KmeshConfigMap   *ebpf.Map `ebpf:"kmesh_config_map"`
	KmeshEndpoint    *ebpf.Map `ebpf:"kmesh_endpoint"`
	KmeshEvents      *ebpf.Map `ebpf:"kmesh_events"`
	KmeshFrontend    *ebpf.Map `ebpf:"kmesh_frontend"`
	KmeshManage      *ebpf.Map `ebpf:"kmesh_manage"`
	KmeshService     *ebpf.Map `ebpf:"kmesh_service"`
	MapOfAuth        *ebpf.Map `ebpf:"map_of_auth"`
	MapOfAuthz       *ebpf.Map `ebpf:"map_of_authz"`
	MapOfSockStorage *ebpf.Map `ebpf:"map_of_sock_storage"`
	MapOfTuple       *ebpf.Map `ebpf:"map_of_tuple"`
	MapOfWlPolicy    *ebpf.Map `ebpf:"map_of_wl_policy"`
	OuterMap         *ebpf.Map `ebpf:"outer_map"`
	TmpBuf           *ebpf.Map `ebpf:"tmp_buf"`
	TmpLogBuf        *ebpf.Map `ebpf:"tmp_log_buf"`
}

func (m *KmeshXDPAuthMaps) Close() error {
	return _KmeshXDPAuthClose(
		m.InnerMap,
		m.KmeshBackend,
		m.KmeshConfigMap,
		m.KmeshEndpoint,
		m.KmeshEvents,
		m.KmeshFrontend,
		m.KmeshManage,
		m.KmeshService,
		m.MapOfAuth,
		m.MapOfAuthz,
		m.MapOfSockStorage,
		m.MapOfTuple,
		m.MapOfWlPolicy,
		m.OuterMap,
		m.TmpBuf,
		m.TmpLogBuf,
	)
}

// KmeshXDPAuthPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshXDPAuthObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshXDPAuthPrograms struct {
	XdpShutdown *ebpf.Program `ebpf:"xdp_shutdown"`
}

func (p *KmeshXDPAuthPrograms) Close() error {
	return _KmeshXDPAuthClose(
		p.XdpShutdown,
	)
}

func _KmeshXDPAuthClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed kmeshxdpauth_bpfel.o
var _KmeshXDPAuthBytes []byte
