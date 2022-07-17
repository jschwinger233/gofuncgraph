package eventmanager

import (
	"fmt"

	"github.com/jschwinger233/ufuncgraph/internal/bpf"
	log "github.com/sirupsen/logrus"
)

func (m *EventManager) Handle(event bpf.UfuncgraphEvent) (err error) {
	if event.Errno != 0 {
		return fmt.Errorf("event error: %d", event.Errno)
	}

	m.Add(event)
	log.Debugf("added event: %+v", event)
	if m.CloseStack(event) {
		userSpecified, err := m.UserSpecified(event)
		if err != nil {
			return err
		}
		if userSpecified {
			m.PrintStack(event.StackId)
		}
		m.ClearStack(event)
	}

	return
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
	uprobe, err := p.GetUprobe(event)
	if err != nil {
		return
	}
	return uprobe.UserSpecified, nil
}
