package eventhandler

import (
	"context"
	"fmt"

	"github.com/jschwinger233/ufuncgraph/internal/bpf"
	"github.com/jschwinger233/ufuncgraph/internal/symparser"
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
		if gevent.Completed(event) {
			if gevent.IsRootEvent(event) {
				gevent.PrintStack(event.Goid)
			}
			gevent.Clear(event)
		}
	}

	fmt.Printf("completed, detaching uprobes\n")
	return
}
