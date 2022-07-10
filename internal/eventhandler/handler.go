package eventhandler

import (
	"context"
	"fmt"

	"github.com/jschwinger233/ufuncgraph/internal/bpf"
)

type EventHandler struct {
	bin       string
	symInterp *SymInterp
}

func New(bin string) (_ *EventHandler, err error) {
	symInterp, err := NewSymInterp(bin)
	return &EventHandler{
		bin:       bin,
		symInterp: symInterp,
	}, err
}

func (h *EventHandler) Handle(ctx context.Context, ch chan bpf.UfuncgraphEvent) (err error) {

	pool, err := NewGevent()
	if err != nil {
		return
	}

	for event := range ch {
		if event.Errno != 0 {
			return fmt.Errorf("event error: %d", event.Errno)
		}

		pool.Add(event)
		if pool.StackCompleted(event.Goid) {
			pool.PrintStack(event.Goid, h.symInterp)
		}
	}

	fmt.Printf("completed, detaching uprobes\n")
	return
}
