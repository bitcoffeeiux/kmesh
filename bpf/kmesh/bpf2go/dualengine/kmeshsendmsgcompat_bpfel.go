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

type KmeshSendmsgCompatBpfSockTuple struct {
	Ipv4 struct {
		Saddr uint32
		Daddr uint32
		Sport uint16
		Dport uint16
	}
	_ [24]byte
}

type KmeshSendmsgCompatBuf struct{ Data [40]int8 }

type KmeshSendmsgCompatKmeshConfig struct {
	BpfLogLevel uint32
	NodeIp      [4]uint32
	PodGateway  [4]uint32
}

type KmeshSendmsgCompatLogEvent struct {
	Ret uint32
	Msg [255]int8
	_   [1]byte
}

// LoadKmeshSendmsgCompat returns the embedded CollectionSpec for KmeshSendmsgCompat.
func LoadKmeshSendmsgCompat() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_KmeshSendmsgCompatBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load KmeshSendmsgCompat: %w", err)
	}

	return spec, err
}

// LoadKmeshSendmsgCompatObjects loads KmeshSendmsgCompat and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*KmeshSendmsgCompatObjects
//	*KmeshSendmsgCompatPrograms
//	*KmeshSendmsgCompatMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadKmeshSendmsgCompatObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadKmeshSendmsgCompat()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// KmeshSendmsgCompatSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshSendmsgCompatSpecs struct {
	KmeshSendmsgCompatProgramSpecs
	KmeshSendmsgCompatMapSpecs
}

// KmeshSendmsgCompatSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshSendmsgCompatProgramSpecs struct {
	SendmsgProg *ebpf.ProgramSpec `ebpf:"sendmsg_prog"`
}

// KmeshSendmsgCompatMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshSendmsgCompatMapSpecs struct {
	KmeshConfigMap *ebpf.MapSpec `ebpf:"kmesh_config_map"`
	KmeshEvents    *ebpf.MapSpec `ebpf:"kmesh_events"`
	MapOfDstInfo   *ebpf.MapSpec `ebpf:"map_of_dst_info"`
	TmpBuf         *ebpf.MapSpec `ebpf:"tmp_buf"`
	TmpLogBuf      *ebpf.MapSpec `ebpf:"tmp_log_buf"`
}

// KmeshSendmsgCompatObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshSendmsgCompatObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshSendmsgCompatObjects struct {
	KmeshSendmsgCompatPrograms
	KmeshSendmsgCompatMaps
}

func (o *KmeshSendmsgCompatObjects) Close() error {
	return _KmeshSendmsgCompatClose(
		&o.KmeshSendmsgCompatPrograms,
		&o.KmeshSendmsgCompatMaps,
	)
}

// KmeshSendmsgCompatMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshSendmsgCompatObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshSendmsgCompatMaps struct {
	KmeshConfigMap *ebpf.Map `ebpf:"kmesh_config_map"`
	KmeshEvents    *ebpf.Map `ebpf:"kmesh_events"`
	MapOfDstInfo   *ebpf.Map `ebpf:"map_of_dst_info"`
	TmpBuf         *ebpf.Map `ebpf:"tmp_buf"`
	TmpLogBuf      *ebpf.Map `ebpf:"tmp_log_buf"`
}

func (m *KmeshSendmsgCompatMaps) Close() error {
	return _KmeshSendmsgCompatClose(
		m.KmeshConfigMap,
		m.KmeshEvents,
		m.MapOfDstInfo,
		m.TmpBuf,
		m.TmpLogBuf,
	)
}

// KmeshSendmsgCompatPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshSendmsgCompatObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshSendmsgCompatPrograms struct {
	SendmsgProg *ebpf.Program `ebpf:"sendmsg_prog"`
}

func (p *KmeshSendmsgCompatPrograms) Close() error {
	return _KmeshSendmsgCompatClose(
		p.SendmsgProg,
	)
}

func _KmeshSendmsgCompatClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed kmeshsendmsgcompat_bpfel.o
var _KmeshSendmsgCompatBytes []byte
