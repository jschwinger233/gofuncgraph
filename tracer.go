package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/jschwinger233/ufuncgraph/internal/bpf"
	"github.com/jschwinger233/ufuncgraph/internal/eventmanager"
	"github.com/jschwinger233/ufuncgraph/internal/symparser"
	log "github.com/sirupsen/logrus"
)

type Tracer struct {
	bin       string
	wildcards []string
	back      bool
	depth     int

	bpf       *bpf.BPF
	symParser *symparser.SymParser
}

func NewTracer(bin string, wildcards []string, backtrace bool, depth int) (_ *Tracer, err error) {
	bpf := bpf.New()
	if err = bpf.Load(); err != nil {
		return
	}
	symParser, err := symparser.New(bin)
	if err != nil {
		return
	}
	return &Tracer{
		bin:       bin,
		wildcards: wildcards,
		back:      backtrace,
		depth:     depth,

		bpf:       bpf,
		symParser: symParser,
	}, nil
}

func (t *Tracer) Start() (err error) {
	uprobes, err := t.symParser.ParseUprobes(t.wildcards, t.depth)
	if err != nil {
		return
	}
	log.Infof("found %d uprobes\n", len(uprobes))

	if err = t.bpf.Attach(t.bin, uprobes); err != nil {
		return
	}

	defer t.bpf.Detach()
	log.Info("start tracing\n")

	eventManager, err := eventmanager.New(uprobes, t.symParser)
	if err != nil {
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	for event := range t.bpf.PollEvents(ctx) {
		if err = eventManager.Handle(event); err != nil {
			break
		}
	}
	eventManager.PrintRemaining()
	return
}
