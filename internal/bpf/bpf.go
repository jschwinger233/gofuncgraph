package bpf

import (
	"context"
	"fmt"
	"io"
	"time"

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
	for _, uprobe := range uprobes {
		switch uprobe.Location {
		case symparser.AtEntry:
			err = b.AttachUprobe(bin, uprobe.Offset)
			if err == nil {
				err = b.AttachUretprobe(bin, uprobe.Offset)
			}
		case symparser.AtRet:
			err = b.AttachRet(bin, uprobe.Offset)
		case symparser.AtFramePointer:
			err = b.AttachFramePointer(bin, uprobe.Offset)
		}
		if err != nil {
			return
		}
	}
	return
}

func (b *BPF) OpenExecutable(bin string) (_ *link.Executable, err error) {
	if _, ok := b.executables[bin]; !ok {
		if b.executables[bin], err = link.OpenExecutable(bin); err != nil {
			return
		}
	}
	return b.executables[bin], nil
}

func (b *BPF) AttachUprobe(bin string, offset uint64) (err error) {
	ex, err := b.OpenExecutable(bin)
	if err != nil {
		return
	}
	uprobe, err := ex.Uprobe("", b.objs.OnEntry, &link.UprobeOptions{Offset: offset})
	if err != nil {
		return err
	}
	b.closers = append(b.closers, uprobe)
	return
}

func (b *BPF) AttachUretprobe(bin string, offset uint64) (err error) {
	ex, err := b.OpenExecutable(bin)
	if err != nil {
		return
	}
	fmt.Printf("uretprobe: %x\n", offset)
	uprobe, err := ex.Uretprobe("", b.objs.OnExit, &link.UprobeOptions{Offset: offset})
	if err != nil {
		return err
	}
	b.closers = append(b.closers, uprobe)
	return
}

func (b *BPF) AttachFramePointer(bin string, offset uint64) (err error) {
	ex, err := b.OpenExecutable(bin)
	if err != nil {
		return
	}
	uprobe, err := ex.Uprobe("", b.objs.OnEntryGolang, &link.UprobeOptions{Offset: offset})
	if err != nil {
		return err
	}
	b.closers = append(b.closers, uprobe)
	return
}

func (b *BPF) AttachRet(bin string, offset uint64) (err error) {
	ex, err := b.OpenExecutable(bin)
	if err != nil {
		return
	}
	uprobe, err := ex.Uprobe("", b.objs.OnExitGolang, &link.UprobeOptions{Offset: offset})
	if err != nil {
		return err
	}
	b.closers = append(b.closers, uprobe)
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
