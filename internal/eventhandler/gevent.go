package eventhandler

import (
	"fmt"
	"time"

	"github.com/elastic/go-sysinfo"
	"github.com/jschwinger233/ufuncgraph/internal/bpf"
	"github.com/jschwinger233/ufuncgraph/internal/symparser"
)

type Gevent struct {
	goroutine2events map[uint64][]bpf.UfuncgraphEvent
	goroutine2stack  map[uint64]uint64
	bootTime         time.Time

	symInterp *SymInterp
	uprobes   []symparser.Uprobe
	cache     map[string]interface{}
}

func NewGevent(uprobes []symparser.Uprobe, symInterp *SymInterp) (_ *Gevent, err error) {
	host, err := sysinfo.Host()
	if err != nil {
		return
	}
	bootTime := host.Info().BootTime
	return &Gevent{
		goroutine2events: map[uint64][]bpf.UfuncgraphEvent{},
		goroutine2stack:  map[uint64]uint64{},
		bootTime:         bootTime,
		symInterp:        symInterp,
		uprobes:          uprobes,
		cache:            map[string]interface{}{},
	}, nil
}

func (p *Gevent) Add(event bpf.UfuncgraphEvent) {
	length := len(p.goroutine2events[event.Goid])
	if length == 0 && event.HookPoint == 1 {
		return
	}
	if length > 0 && event.HookPoint == 0 && p.goroutine2events[event.Goid][length-1].HookPoint == 0 && p.goroutine2events[event.Goid][length-1].StackDepth == event.StackDepth {
		return
	}
	p.goroutine2events[event.Goid] = append(p.goroutine2events[event.Goid], event)
	p.goroutine2stack[event.Goid] = p.goroutine2stack[event.Goid] - 2*uint64(event.HookPoint) + 1
}

func (p *Gevent) Completed(event bpf.UfuncgraphEvent) bool {
	return p.goroutine2stack[event.Goid] == 0
}

func (p *Gevent) Clear(event bpf.UfuncgraphEvent) {
	delete(p.goroutine2events, event.Goid)
	delete(p.goroutine2stack, event.Goid)
}

func (p *Gevent) IsRootEvent(event bpf.UfuncgraphEvent) bool {
	roots := p.getRootEventSet()
	_, found := roots[p.symInterp.Interp(event.Ip, withOffset(false))]
	return found
}

func (p *Gevent) getRootEventSet() map[string]interface{} {
	if _, ok := p.cache["rootevents"]; !ok {
		roots := map[string]interface{}{}
		for _, uprobe := range p.uprobes {
			if uprobe.Root {
				roots[uprobe.Funcname] = nil
			}
		}
		p.cache["rootevents"] = roots
	}
	return p.cache["rootevents"].(map[string]interface{})
}

func (p *Gevent) PrintStack(goid uint64) {
	ident := ""
	println()
	for _, event := range p.goroutine2events[goid] {
		t := p.bootTime.Add(time.Duration(event.TimeNs)).Format("2006-01-02 15:04:05.0000")
		if event.HookPoint == 0 {
			fmt.Printf("%s %s %s { %s\n", t, ident, p.symInterp.Interp(event.Ip, withOffset(false)), p.symInterp.Interp(event.CallerIp, withOffset(true)))
			ident += "  "
		} else {
			if len(ident) == 0 {
				continue
			}
			ident = ident[:len(ident)-2]
			fmt.Printf("%s %s } %s\n", t, ident, p.symInterp.Interp(event.Ip, withOffset(true)))
		}
	}
	return
}

func (g *Gevent) PrintAll() {
	for goid := range g.goroutine2events {
		g.PrintStack(goid)
	}
}
