package eventmanager

import (
	"strings"
	"time"

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
	uprobe, err := m.GetUprobe(event)
	if err != nil {
		log.Errorf("failed to get uprobe for event %+v: %+v", event, err)
		return
	}
	if length > 0 {
		lastEvent := m.goEvents[event.Goid][length-1]
		if lastEvent.Ip == event.Ip && lastEvent.Bp != event.CallerBp {
			// duplicated entry event due to stack expansion/shrinkage
			log.Debugf("duplicated entry event: %+v", event)
			m.goEvents[event.Goid][length-1].GofuncgraphEvent = event
			for range uprobe.FetchArgs {
				<-m.goArgs[event.Goid]
			}
			return
		}
	}

	args := []string{}
	for _, fetchArg := range uprobe.FetchArgs {
		for m.goArgs[event.Goid] == nil {
			time.Sleep(time.Millisecond)
		}
		arg := <-m.goArgs[event.Goid]
		if len(args) > 0 {
			args = append(args, ", ")
		}
		args = append(args, fetchArg.Varname, "=", fetchArg.SprintValue(arg.Data[:]))
	}
	m.goEvents[event.Goid] = append(m.goEvents[event.Goid], Event{
		GofuncgraphEvent: event,
		uprobe:           &uprobe,
		argString:        strings.Join(args, ""),
	})
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
