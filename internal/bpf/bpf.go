package bpf

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/jschwinger233/ufuncgraph/internal/symparser"
	dynamicstruct "github.com/ompluscator/dynamic-struct"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type event Ufuncgraph ./ufuncgraph.c -- -I./headers

const (
	BpfInsertIndex        = 81
	EventDataOffset int64 = 436
	VacantR10Offset       = -96
)

type BPF struct {
	executables map[string]*link.Executable
	objs        interface{}
	closers     []io.Closer
}

func New() *BPF {
	return &BPF{
		executables: map[string]*link.Executable{},
		objs:        &UfuncgraphObjects{},
	}
}

func (b *BPF) Load(uprobes []symparser.Uprobe) (err error) {
	structDefine := dynamicstruct.NewStruct().
		AddField("Entpoint", &ebpf.Program{}, `ebpf:"entpoint"`).
		AddField("EntpointWithBt", &ebpf.Program{}, `ebpf:"entpoint_with_bt"`).
		AddField("Retpoint", &ebpf.Program{}, `ebpf:"retpoint"`).
		AddField("BpfStack", &ebpf.Map{}, `ebpf:"bpf_stack"`).
		AddField("EventQueue", &ebpf.Map{}, `ebpf:"event_queue"`).
		AddField("Goids", &ebpf.Map{}, `ebpf:"goids"`)

	spec, err := LoadUfuncgraph()
	if err != nil {
		return err
	}

	for _, uprobe := range uprobes {
		if uprobe.Location != symparser.AtFramePointer || len(uprobe.FetchArgs) == 0 {
			continue
		}
		fieldPrefix, progPrefix := "Entpoint", "entpoint"
		if uprobe.Backtrace {
			fieldPrefix, progPrefix = "EntpointWithBt", "entpoint_with_bt"
		}
		suffix := fmt.Sprintf("_%x", uprobe.Offset)
		progName := progPrefix + suffix
		structDefine.AddField(fieldPrefix+suffix, &ebpf.Program{}, fmt.Sprintf(`ebpf:"%s"`, progName))
		spec.Programs[progName] = spec.Programs["entpoint"].Copy()
		instructions := []asm.Instruction{}
		eventOffset := EventDataOffset
		for _, args := range uprobe.FetchArgs {
			instructions = append(instructions, args.CompileBpfInstructions(VacantR10Offset, eventOffset)...)
			eventOffset += int64(args.Size)
		}

		spec.Programs[progName].Instructions = append(spec.Programs[progName].Instructions[:BpfInsertIndex], append(instructions, spec.Programs[progName].Instructions[BpfInsertIndex:]...)...)
		spec.Programs[progName].Instructions[13].Offset += int16(len(instructions))
	}
	b.objs = structDefine.Build().New()

	return spec.LoadAndAssign(b.objs, nil)
	// TODO@zc: closer
	//b.closers = append(b.closers, b.objs)
}

func (b *BPF) Attach(bin string, uprobes []symparser.Uprobe) (err error) {
	ex, err := link.OpenExecutable(bin)
	if err != nil {
		return
	}
	reader := dynamicstruct.NewReader(b.objs)
	for _, uprobe := range uprobes {
		var prog *ebpf.Program
		switch uprobe.Location {
		case symparser.AtFramePointer:
			suffix := ""
			if len(uprobe.FetchArgs) > 0 {
				suffix = fmt.Sprintf("_%x", uprobe.Offset)
			}
			if uprobe.Backtrace {
				prog = reader.GetField("EntpointWithBt" + suffix).Interface().(*ebpf.Program)
			} else {
				prog = reader.GetField("Entpoint" + suffix).Interface().(*ebpf.Program)
			}
		case symparser.AtRet:
			prog = reader.GetField("Retpoint").Interface().(*ebpf.Program)
		}
		uprobe, err := ex.Uprobe("", prog, &link.UprobeOptions{Offset: uprobe.Offset})
		if err != nil {
			return err
		}
		b.closers = append(b.closers, uprobe)

	}
	return
}

func (b *BPF) Detach() {
	for _, closer := range b.closers {
		closer.Close()
	}
}

func (b *BPF) PollEvents(ctx context.Context) chan UfuncgraphEvent {
	ch := make(chan UfuncgraphEvent)

	queue := dynamicstruct.NewReader(b.objs).GetField("EventQueue").Interface().(*ebpf.Map)
	go func() {
		defer close(ch)
		for {
			event := UfuncgraphEvent{}
			select {
			case <-ctx.Done():
				return
			default:
				if err := queue.LookupAndDelete(nil, &event); err != nil {
					time.Sleep(time.Millisecond)
					continue
				}
				ch <- event
			}
		}
	}()
	return ch
}
