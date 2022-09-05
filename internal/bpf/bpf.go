package bpf

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/jschwinger233/gofuncgraph/internal/uprobe"
	dynamicstruct "github.com/ompluscator/dynamic-struct"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type event Gofuncgraph ./gofuncgraph.c -- -I./headers

const (
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
	}
}

func (b *BPF) Load(uprobes []uprobe.Uprobe) (err error) {
	structDefine := dynamicstruct.NewStruct().
		AddField("Ent", &ebpf.Program{}, `ebpf:"ent"`).
		AddField("EntBt", &ebpf.Program{}, `ebpf:"ent_bt"`).
		AddField("Custom", &ebpf.Program{}, `ebpf:"custom"`).
		AddField("Ret", &ebpf.Program{}, `ebpf:"ret"`).
		AddField("BpfStack", &ebpf.Map{}, `ebpf:"bpf_stack"`).
		AddField("EventQueue", &ebpf.Map{}, `ebpf:"event_queue"`).
		AddField("Goids", &ebpf.Map{}, `ebpf:"goids"`)

	spec, err := LoadGofuncgraph()
	if err != nil {
		return err
	}

	for _, up := range uprobes {
		if (up.Location == uprobe.AtRet) || len(up.FetchArgs) == 0 {
			continue
		}
		fieldPrefix, progPrefix := "Ent", "ent"
		if up.Location == uprobe.AtCustom {
			fieldPrefix, progPrefix = "Custom", "custom"
		}
		if up.Backtrace {
			fieldPrefix, progPrefix = fieldPrefix+"Bt", progPrefix+"_bt"
		}
		suffix := fmt.Sprintf("_%x", up.AbsOffset)
		progName := progPrefix + suffix
		structDefine.AddField(fieldPrefix+suffix, &ebpf.Program{}, fmt.Sprintf(`ebpf:"%s"`, progName))
		spec.Programs[progName] = spec.Programs[progPrefix].Copy()
		instructions := []asm.Instruction{}
		eventOffset := EventDataOffset
		for _, args := range up.FetchArgs {
			instructions = append(instructions, args.CompileBpfInstructions(VacantR10Offset, eventOffset)...)
			eventOffset += int64(args.Size)
		}

		bpfInsertIndex := 0
		for bpfInsertIndex = range spec.Programs[progName].Instructions {
			inst := spec.Programs[progName].Instructions[bpfInsertIndex]
			if inst.OpCode == 123 && inst.Dst == asm.R6 && inst.Src == asm.R7 && inst.Offset == 0 { // *(u64 *)(r6 + 0) = r7
				break
			}
		}
		bpfInsertIndex += 2 // skip the "e->location = location" / "*(u8 *)(r6 + 34) = r1"

		spec.Programs[progName].Instructions = append(spec.Programs[progName].Instructions[:bpfInsertIndex], append(instructions, spec.Programs[progName].Instructions[bpfInsertIndex:]...)...)

		for i, ins := range spec.Programs[progName].Instructions {
			if ins.OpCode == 21 { // goto
				if i < bpfInsertIndex && spec.Programs[progName].Instructions[i].Offset >= int16(bpfInsertIndex) {
					spec.Programs[progName].Instructions[i].Offset += int16(len(instructions))
				}
			}
		}
	}
	b.objs = structDefine.Build().New()

	defer func() {
		if err != nil {
			return
		}
		reader := dynamicstruct.NewReader(b.objs)
		b.closers = append(b.closers, reader.GetField("EventQueue").Interface().(*ebpf.Map))
		b.closers = append(b.closers, reader.GetField("BpfStack").Interface().(*ebpf.Map))
		b.closers = append(b.closers, reader.GetField("Goids").Interface().(*ebpf.Map))
	}()
	return spec.LoadAndAssign(b.objs, nil)
}

func (b *BPF) Attach(bin string, uprobes []uprobe.Uprobe) (err error) {
	ex, err := link.OpenExecutable(bin)
	if err != nil {
		return
	}
	reader := dynamicstruct.NewReader(b.objs)
	for _, up := range uprobes {
		var prog *ebpf.Program
		switch up.Location {
		case uprobe.AtFramePointer:
			suffix := ""
			if len(up.FetchArgs) > 0 {
				suffix = fmt.Sprintf("_%x", up.AbsOffset)
			}
			if up.Backtrace {
				prog = reader.GetField("EntBt" + suffix).Interface().(*ebpf.Program)
			} else {
				prog = reader.GetField("Ent" + suffix).Interface().(*ebpf.Program)
			}
		case uprobe.AtCustom:
			suffix := ""
			if len(up.FetchArgs) > 0 {
				suffix = fmt.Sprintf("_%x", up.AbsOffset)
			}
			prog = reader.GetField("Custom" + suffix).Interface().(*ebpf.Program)
		case uprobe.AtRet:
			prog = reader.GetField("Ret").Interface().(*ebpf.Program)
		}
		up, err := ex.Uprobe("", prog, &link.UprobeOptions{Offset: up.AbsOffset})
		if err != nil {
			return err
		}
		b.closers = append(b.closers, up)

	}
	return
}

func (b *BPF) Detach() {
	for _, closer := range b.closers {
		closer.Close()
	}
}

func (b *BPF) PollEvents(ctx context.Context) chan GofuncgraphEvent {
	ch := make(chan GofuncgraphEvent)

	queue := dynamicstruct.NewReader(b.objs).GetField("EventQueue").Interface().(*ebpf.Map)
	go func() {
		defer close(ch)
		for {
			event := GofuncgraphEvent{}
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
