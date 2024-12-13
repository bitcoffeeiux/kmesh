// Code generated by bpf2go; DO NOT EDIT.
//go:build mips || mips64 || ppc64 || s390x

package general

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type KmeshTcMarkEncryptCompatBuf struct{ Data [40]int8 }

type KmeshTcMarkEncryptCompatKmeshConfig struct {
	BpfLogLevel      uint32
	NodeIp           [4]uint32
	PodGateway       [4]uint32
	AuthzOffload     uint32
	EnableMonitoring uint32
}

type KmeshTcMarkEncryptCompatLpmKey struct {
	TrieKey struct {
		Prefixlen uint32
		Data      [0]uint8
	}
	Ip struct {
		Ip4 uint32
		_   [12]byte
	}
}

type KmeshTcMarkEncryptCompatNodeinfo struct {
	Spi    uint32
	Nodeid uint16
	_      [2]byte
}

// LoadKmeshTcMarkEncryptCompat returns the embedded CollectionSpec for KmeshTcMarkEncryptCompat.
func LoadKmeshTcMarkEncryptCompat() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_KmeshTcMarkEncryptCompatBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load KmeshTcMarkEncryptCompat: %w", err)
	}

	return spec, err
}

// LoadKmeshTcMarkEncryptCompatObjects loads KmeshTcMarkEncryptCompat and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*KmeshTcMarkEncryptCompatObjects
//	*KmeshTcMarkEncryptCompatPrograms
//	*KmeshTcMarkEncryptCompatMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadKmeshTcMarkEncryptCompatObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadKmeshTcMarkEncryptCompat()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// KmeshTcMarkEncryptCompatSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshTcMarkEncryptCompatSpecs struct {
	KmeshTcMarkEncryptCompatProgramSpecs
	KmeshTcMarkEncryptCompatMapSpecs
}

// KmeshTcMarkEncryptCompatSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshTcMarkEncryptCompatProgramSpecs struct {
	TcMarkEncrypt *ebpf.ProgramSpec `ebpf:"tc_mark_encrypt"`
}

// KmeshTcMarkEncryptCompatMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshTcMarkEncryptCompatMapSpecs struct {
	KmConfigmap   *ebpf.MapSpec `ebpf:"km_configmap"`
	KmLogEvent    *ebpf.MapSpec `ebpf:"km_log_event"`
	KmTmpbuf      *ebpf.MapSpec `ebpf:"km_tmpbuf"`
	MapOfNodeinfo *ebpf.MapSpec `ebpf:"map_of_nodeinfo"`
}

// KmeshTcMarkEncryptCompatObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshTcMarkEncryptCompatObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshTcMarkEncryptCompatObjects struct {
	KmeshTcMarkEncryptCompatPrograms
	KmeshTcMarkEncryptCompatMaps
}

func (o *KmeshTcMarkEncryptCompatObjects) Close() error {
	return _KmeshTcMarkEncryptCompatClose(
		&o.KmeshTcMarkEncryptCompatPrograms,
		&o.KmeshTcMarkEncryptCompatMaps,
	)
}

// KmeshTcMarkEncryptCompatMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshTcMarkEncryptCompatObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshTcMarkEncryptCompatMaps struct {
	KmConfigmap   *ebpf.Map `ebpf:"km_configmap"`
	KmLogEvent    *ebpf.Map `ebpf:"km_log_event"`
	KmTmpbuf      *ebpf.Map `ebpf:"km_tmpbuf"`
	MapOfNodeinfo *ebpf.Map `ebpf:"map_of_nodeinfo"`
}

func (m *KmeshTcMarkEncryptCompatMaps) Close() error {
	return _KmeshTcMarkEncryptCompatClose(
		m.KmConfigmap,
		m.KmLogEvent,
		m.KmTmpbuf,
		m.MapOfNodeinfo,
	)
}

// KmeshTcMarkEncryptCompatPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshTcMarkEncryptCompatObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshTcMarkEncryptCompatPrograms struct {
	TcMarkEncrypt *ebpf.Program `ebpf:"tc_mark_encrypt"`
}

func (p *KmeshTcMarkEncryptCompatPrograms) Close() error {
	return _KmeshTcMarkEncryptCompatClose(
		p.TcMarkEncrypt,
	)
}

func _KmeshTcMarkEncryptCompatClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed kmeshtcmarkencryptcompat_bpfeb.o
var _KmeshTcMarkEncryptCompatBytes []byte
