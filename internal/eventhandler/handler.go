package eventhandler

import (
	"context"
	"fmt"

	"github.com/jschwinger233/ufuncgraph/internal/bpf"
	"github.com/jschwinger233/ufuncgraph/internal/symparser"
	log "github.com/sirupsen/logrus"
)

type EventHandler struct {
	bin string
}

func New(bin string) *EventHandler {
	return &EventHandler{
		bin: bin,
	}
}

func (h *EventHandler) Handle(ctx context.Context, ch chan bpf.UfuncgraphEvent, uprobes []symparser.Uprobe) (err error) {
	symInterp, err := NewSymInterp(h.bin)
	if err != nil {
		return
	}
	gevent, err := NewGevent(uprobes, symInterp)
	if err != nil {
		return
	}

	for event := range ch {
		if event.Errno != 0 {
			return fmt.Errorf("event error: %d", event.Errno)
		}

		gevent.Add(event)
		log.Debugf("add event: %+v", event)
		if gevent.Completed(event) {
			if true {
				//if gevent.IsRootEvent(event) {
				gevent.PrintStack(event.StackId)
			}
			gevent.Clear(event)
		}
	}

	gevent.PrintAll()

	log.Info("interrupted, detaching uprobes\n")
	return
}
