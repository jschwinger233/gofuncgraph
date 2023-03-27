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

func (m *EventManager) Add(event bpf.GofuncgraphEvent) {
	length := len(m.goEvents[event.Goid])
	if length == 0 && event.Location != 0 {
		return
	}
	if length > 0 {
		lastEvent := m.goEvents[event.Goid][length-1]
		if lastEvent.Ip == event.Ip && lastEvent.Bp != event.CallerBp {
			// duplicated entry event due to stack expansion
			return
		}
	}
	m.goEvents[event.Goid] = append(m.goEvents[event.Goid], event)
	switch event.Location {
	case 0:
		m.goEventStack[event.Goid]++
	case 1:
		m.goEventStack[event.Goid]--
	}
}

func (m *EventManager) CloseStack(event bpf.GofuncgraphEvent) bool {
	return m.goEventStack[event.Goid] == 0 && len(m.goEvents[event.Goid]) > 0
}

func (m *EventManager) ClearStack(event bpf.GofuncgraphEvent) {
	delete(m.goEvents, event.Goid)
	delete(m.goEventStack, event.Goid)
}
