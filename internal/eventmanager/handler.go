package eventmanager

import (
	"fmt"

	"github.com/jschwinger233/gofuncgraph/internal/bpf"
	log "github.com/sirupsen/logrus"
)

func (m *EventManager) Handle(event bpf.GofuncgraphEvent) (err error) {
	if event.Errno != 0 {
		return fmt.Errorf("event error: %d", event.Errno)
	}

	m.Add(event)
	log.Debugf("added event: %+v", event)
	if m.CloseStack(event) {
		userSpecified, err := m.UserSpecified(m.goroutine2events[event.StackId][0])
		if err != nil {
			return err
		}
		if userSpecified {
			if err = m.PrintStack(event.StackId); err != nil {
				return err
			}
		}
		m.ClearStack(event)
	}

	return
}

func (p *EventManager) Add(event bpf.GofuncgraphEvent) {
	length := len(p.goroutine2events[event.StackId])
	if length == 0 && (event.Location == 1 || event.Location == 2) {
		return
	}
	if event.StackDepth != 65535 && length > 0 && event.Location == 0 && p.goroutine2events[event.StackId][length-1].Location == 0 && p.goroutine2events[event.StackId][length-1].StackDepth == event.StackDepth && p.goroutine2events[event.StackId][length-1].Ip == event.Ip {
		// duplicated entry event due to stack expansion
		return
	}
	p.goroutine2events[event.StackId] = append(p.goroutine2events[event.StackId], event)
	switch event.Location {
	case 0:
		p.goroutine2stack[event.StackId]++
	case 1:
		p.goroutine2stack[event.StackId]--
	case 2:
		// do nothing
	}
}

func (p *EventManager) CloseStack(event bpf.GofuncgraphEvent) bool {
	return p.goroutine2stack[event.StackId] == 0 && len(p.goroutine2events[event.StackId]) > 0
}

func (p *EventManager) ClearStack(event bpf.GofuncgraphEvent) {
	delete(p.goroutine2events, event.StackId)
	delete(p.goroutine2stack, event.StackId)
}

func (p *EventManager) UserSpecified(event bpf.GofuncgraphEvent) (_ bool, err error) {
	uprobe, err := p.GetUprobe(event)
	if err != nil {
		return
	}
	return uprobe.UserSpecified, nil
}
