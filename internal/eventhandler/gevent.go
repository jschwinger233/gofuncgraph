package eventhandler

import (
	"fmt"
	"time"

	"github.com/elastic/go-sysinfo"
	"github.com/jschwinger233/ufuncgraph/internal/bpf"
)

type Gevent struct {
	goroutine2events map[uint64][]bpf.UfuncgraphEvent
	goroutine2stack  map[uint64]uint64
	bootTime         time.Time
}

func NewGevent() (_ *Gevent, err error) {
	host, err := sysinfo.Host()
	if err != nil {
		return
	}
	bootTime := host.Info().BootTime
	return &Gevent{
		goroutine2events: map[uint64][]bpf.UfuncgraphEvent{},
		goroutine2stack:  map[uint64]uint64{},
		bootTime:         bootTime,
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

func (p *Gevent) StackCompleted(goid uint64) bool {
	return p.goroutine2stack[goid] == 0
}

func (p *Gevent) PrintStack(goid uint64, symInterp *SymInterp) {
	ident := ""
	println()
	for _, event := range p.goroutine2events[goid] {
		t := p.bootTime.Add(time.Duration(event.TimeNs)).Format("2006-01-02 15:04:05.0000")
		if event.HookPoint == 0 {
			fmt.Printf("%s %s %s { %s\n", t, ident, symInterp.Interp(event.Ip, withOffset(false)), symInterp.Interp(event.CallerIp, withOffset(true)))
			ident += "  "
		} else {
			if len(ident) == 0 {
				continue
			}
			ident = ident[:len(ident)-2]
			fmt.Printf("%s %s } %s\n", t, ident, symInterp.Interp(event.Ip, withOffset(true)))
		}
	}
	delete(p.goroutine2events, goid)
	return
}
