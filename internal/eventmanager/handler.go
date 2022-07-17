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
