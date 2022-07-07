package main

import (
	"context"

	"github.com/jschwinger233/ufuncgraph/bpf"
)

type Functracer struct {
	bpf     *bpf.BPF
	binPath string
}

func (t *Functracer) LoadBPF() (err error) {
	t.bpf = bpf.New()
	return t.bpf.LoadBPF()
}

func (t *Functracer) AttachUprobes(binPath string, wildcards []string) (err error) {
	entryOffsets, exitOffsets, err := ParseOffsets(binPath, wildcards)
	if err != nil {
		return
	}
	if err = t.bpf.AttachEntry(binPath, entryOffsets); err != nil {
		return
	}
	if err = t.bpf.AttachExit(binPath, exitOffsets); err != nil {
		return
	}
	t.binPath = binPath
	return
}

func (t *Functracer) DetachUprobes() {
	t.bpf.Detach()
}

func (t *Functracer) CollectEvents(ctx context.Context) (err error) {
	ch := t.bpf.PollEvents(ctx)
	FuncgraphStream(ch, t.binPath)
	return
}
