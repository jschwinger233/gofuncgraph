package bpf

import (
	"context"
	"io"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/jschwinger233/ufuncgraph/internal/symparser"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type event Ufuncgraph ./ufuncgraph.c -- -I./headers

type BPF struct {
	objs        *UfuncgraphObjects
	executables map[string]*link.Executable
	closers     []io.Closer
}

func New() *BPF {
	return &BPF{
		executables: map[string]*link.Executable{},
	}
}

func (b *BPF) Load() (err error) {
	objs := UfuncgraphObjects{}
	if err = LoadUfuncgraphObjects(&objs, nil); err != nil {
		return
	}
	b.closers = append(b.closers, &objs)
	b.objs = &objs
	return
}

func (b *BPF) Attach(bin string, uprobes []symparser.Uprobe) (err error) {
	ex, err := link.OpenExecutable(bin)
	if err != nil {
		return
	}
	for _, uprobe := range uprobes {
		var prog *ebpf.Program
		switch uprobe.Location {
		case symparser.AtFramePointer:
			prog = b.objs.Entpoint
		case symparser.AtRet:
			prog = b.objs.Retpoint
		}
		uprobe, err := ex.Uprobe("", prog, &link.UprobeOptions{Offset: uprobe.Offset})
		if err != nil {
			return err
		}
		b.closers = append(b.closers, uprobe)

	}
	return
}

func (b *BPF) Detach() {
	for _, closer := range b.closers {
		closer.Close()
	}
}

func (b *BPF) PollEvents(ctx context.Context) chan UfuncgraphEvent {
	ch := make(chan UfuncgraphEvent)
	go func() {
		defer close(ch)
		for {
			event := UfuncgraphEvent{}
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
