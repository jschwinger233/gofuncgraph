package eventmanager

import (
	"github.com/jschwinger233/gofuncgraph/internal/bpf"
	log "github.com/sirupsen/logrus"
)

func (m *EventManager) Handle(event bpf.GofuncgraphEvent) (err error) {
	m.Add(event)
	log.Debugf("added event: %+v", event)
	if m.CloseStack(event) {
		if err = m.PrintStack(event.Goid); err != nil {
			return err
		}
		m.ClearStack(event)
	}
	return
}

func (p *EventManager) Add(event bpf.GofuncgraphEvent) {
	length := len(p.goroutine2events[event.Goid])
	if length == 0 && event.Location != 0 {
		return
	}
	if length > 0 {
		lastEvent := p.goroutine2events[event.Goid][length-1]
		if lastEvent.Ip == event.Ip && lastEvent.Bp != event.CallerBp {
			// duplicated entry event due to stack expansion
			return
		}
	}
	p.goroutine2events[event.Goid] = append(p.goroutine2events[event.Goid], event)
	switch event.Location {
	case 0:
		p.goroutine2stack[event.Goid]++
	case 1:
		p.goroutine2stack[event.Goid]--
	}
}

func (p *EventManager) CloseStack(event bpf.GofuncgraphEvent) bool {
	return p.goroutine2stack[event.Goid] == 0 && len(p.goroutine2events[event.Goid]) > 0
}

func (p *EventManager) ClearStack(event bpf.GofuncgraphEvent) {
	delete(p.goroutine2events, event.Goid)
	delete(p.goroutine2stack, event.Goid)
}
