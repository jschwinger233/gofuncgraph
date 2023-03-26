package bpf

import (
	"context"
	"io"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/jschwinger233/gofuncgraph/internal/uprobe"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type event Gofuncgraph ./gofuncgraph.c -- -I./headers

const (
	EventDataOffset int64 = 436
	VacantR10Offset       = -96
)

type BPF struct {
	executables map[string]*link.Executable
	objs        *GofuncgraphObjects
	closers     []io.Closer
}

func New() *BPF {
	return &BPF{
		executables: map[string]*link.Executable{},
	}
}

func (b *BPF) Load(uprobes []uprobe.Uprobe) (err error) {
	spec, err := LoadGofuncgraph()
	if err != nil {
		return err
	}

	b.objs = &GofuncgraphObjects{}
	defer func() {
		if err != nil {
			return
		}
		b.closers = append(b.closers, b.objs.EventQueue)
		b.closers = append(b.closers, b.objs.EventStack)
	}()
	return spec.LoadAndAssign(b.objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSize: ebpf.DefaultVerifierLogSize * 4},
	})
}

func (b *BPF) Attach(bin string, uprobes []uprobe.Uprobe) (err error) {
	ex, err := link.OpenExecutable(bin)
	if err != nil {
		return
	}
	for _, up := range uprobes {
		var prog *ebpf.Program
		switch up.Location {
		case uprobe.AtEntry:
			prog = b.objs.Ent
		case uprobe.AtRet:
			prog = b.objs.Ret
		}
		up, err := ex.Uprobe("", prog, &link.UprobeOptions{Offset: up.AbsOffset})
		if err != nil {
			return err
		}
		b.closers = append(b.closers, up)

	}
	return
}

func (b *BPF) Detach() {
	for _, closer := range b.closers {
		closer.Close()
	}
}

func (b *BPF) PollEvents(ctx context.Context) chan GofuncgraphEvent {
	ch := make(chan GofuncgraphEvent)

	go func() {
		defer close(ch)
		for {
			event := GofuncgraphEvent{}
			select {
			case <-ctx.Done():
				return
			default:
				if err := b.objs.EventQueue.LookupAndDelete(nil, &event); err != nil {
					time.Sleep(time.Millisecond)
					continue
				}
				ch <- event
			}
		}
	}()
	return ch
}
