package eventmanager

import (
	"errors"
	"fmt"
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

func (p *EventManager) Add(event bpf.UfuncgraphEvent) {
	length := len(p.goroutine2events[event.StackId])
	if length == 0 && event.Location == 1 {
		return
	}
	if length > 0 && event.Location == 0 && p.goroutine2events[event.StackId][length-1].Location == 0 && p.goroutine2events[event.StackId][length-1].StackDepth == event.StackDepth {
		return
	}
	p.goroutine2events[event.StackId] = append(p.goroutine2events[event.StackId], event)
	p.goroutine2stack[event.StackId] = p.goroutine2stack[event.StackId] - 2*uint64(event.Location) + 1
}

func (p *EventManager) CloseStack(event bpf.UfuncgraphEvent) bool {
	return p.goroutine2stack[event.StackId] == 0
}

func (p *EventManager) ClearStack(event bpf.UfuncgraphEvent) {
	delete(p.goroutine2events, event.StackId)
	delete(p.goroutine2stack, event.StackId)
}

func (p *EventManager) UserSpecified(event bpf.UfuncgraphEvent) (_ bool, err error) {
	sym, _, err := p.symparser.ResolveAddress(event.Ip)
	if err != nil {
		return
	}
	uprobe, ok := p.uprobes[sym.Name]
	if !ok {
		err = errors.New("uprobe not found")
		return
	}
	return uprobe.UserSpecified, nil
}

func (p *EventManager) PrintStack(StackId uint64) (err error) {
	indent := ""
	println()
	for _, event := range p.goroutine2events[StackId] {
		t := p.bootTime.Add(time.Duration(event.TimeNs)).Format("2006-01-02 15:04:05.0000")
		sym, offset, err := p.symparser.ResolveAddress(event.Ip)
		if err != nil {
			return err
		}
		callerSym, callerOffset, err := p.symparser.ResolveAddress(event.CallerIp)
		if err != nil {
			return err
		}
		if event.Location == 0 {
			fmt.Printf("%s %s %s+%d { %s+%d\n", t, indent, sym.Name, offset, callerSym.Name, callerOffset)
			indent += "  "
		} else {
			if len(indent) == 0 {
				continue
			}
			indent = indent[:len(indent)-2]
			fmt.Printf("%s %s } %s+%d\n", t, indent, sym.Name, offset)
		}
	}
	return
}

func (g *EventManager) PrintRemaining() {
	for StackId := range g.goroutine2events {
		g.PrintStack(StackId)
	}
}
