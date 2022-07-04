package bpf

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type event Ufuncgraph ./ufuncgraph.c -- -I./headers

type BPF struct {
	objs    *UfuncgraphObjects
	closers []io.Closer
}

func New() *BPF {
	return &BPF{}
}

func (b *BPF) LoadBPF() (err error) {
	objs := UfuncgraphObjects{}
	if err = LoadUfuncgraphObjects(&objs, nil); err != nil {
		return
	}
	b.closers = append(b.closers, &objs)
	b.objs = &objs
	return
}

func (b *BPF) AttachEntry(binPath string, offsets []uint64) (err error) {
	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		return
	}
	for _, offset := range offsets {
		uprobe, err := ex.Uprobe("", b.objs.OnEntry, &link.UprobeOptions{Offset: offset})
		if err != nil {
			return err
		}
		b.closers = append(b.closers, uprobe)
	}
	fmt.Printf("attached %d entry uprobes\n", len(offsets))
	return
}

func (b *BPF) AttachExit(binPath string, offsets []uint64) (err error) {
	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		return
	}
	for _, offset := range offsets {
		uprobe, err := ex.Uprobe("", b.objs.OnExit, &link.UprobeOptions{Offset: offset})
		if err != nil {
			return err
		}
		b.closers = append(b.closers, uprobe)
	}
	fmt.Printf("attached %d exit uprobes\n", len(offsets))
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
