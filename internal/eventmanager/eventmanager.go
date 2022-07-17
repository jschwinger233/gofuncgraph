package eventmanager

import (
	"errors"
	"time"

	"github.com/elastic/go-sysinfo"
	"github.com/jschwinger233/ufuncgraph/internal/bpf"
	"github.com/jschwinger233/ufuncgraph/internal/symparser"
)

type EventManager struct {
	symparser *symparser.SymParser
	uprobes   map[string]symparser.Uprobe

	goroutine2events map[uint64][]bpf.UfuncgraphEvent
	goroutine2stack  map[uint64]uint64
	bootTime         time.Time
}

func New(uprobes []symparser.Uprobe, parser *symparser.SymParser) (_ *EventManager, err error) {
	host, err := sysinfo.Host()
	if err != nil {
		return
	}
	bootTime := host.Info().BootTime
	uprobesMap := map[string]symparser.Uprobe{}
	for _, uprobe := range uprobes {
		if uprobe.Location == symparser.AtFramePointer {
			uprobesMap[uprobe.Funcname] = uprobe
		}
	}
	return &EventManager{
		symparser:        parser,
		goroutine2events: map[uint64][]bpf.UfuncgraphEvent{},
		goroutine2stack:  map[uint64]uint64{},
		bootTime:         bootTime,
		uprobes:          uprobesMap,
	}, nil
}

func (p *EventManager) GetUprobe(event bpf.UfuncgraphEvent) (_ symparser.Uprobe, err error) {
	sym, _, err := p.symparser.ResolveAddress(event.Ip)
	if err != nil {
		return
	}
	uprobe, ok := p.uprobes[sym.Name]
	if !ok {
		err = errors.New("uprobe not found")
		return
	}
	return uprobe, nil
}
