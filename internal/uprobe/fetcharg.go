package uprobe

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/asm"
)

type FetchArg struct {
	Varname   string
	Statement string
	Type      string
	Size      int
	Ops       []FetchOp
}

func parseFetchArgs(fetch map[string]map[string]string) (fetchArgs map[string][]*FetchArg, err error) {
	fetchArgs = map[string][]*FetchArg{}
	for funcname, fet := range fetch {
		for name, statement := range fet {
			fa, err := newFetchArg(name, statement)
			if err != nil {
				return nil, err
			}
			fetchArgs[funcname] = append(fetchArgs[funcname], fa)
		}
	}
	return
}

func newFetchArg(varname, statement string) (_ *FetchArg, err error) {
	parts := strings.Split(statement, ":")
	if len(parts) != 2 {
		err = fmt.Errorf("type not found: %s", statement)
		return
	}
	switch parts[1][0] {
	case 'u', 's':
		if !(parts[1][1:] == "8" || parts[1][1:] == "16" || parts[1][1:] == "32" || parts[1][1:] == "64") {
			err = fmt.Errorf("only support 8/16/32/64 bits for u/s type: %s", parts[1])
			return
		}
	case 'c':
		if !(parts[1][1:] == "8" || parts[1][1:] == "16" || parts[1][1:] == "32" || parts[1][1:] == "64" || parts[1][1:] == "128" || parts[1][1:] == "256") {
			err = fmt.Errorf("only support 8/16/32/64/128/256 bits for c type: %s", parts[1])
			return
		}
	default:
		err = fmt.Errorf("only support u/s/c type: %s", parts[1])
		return
	}

	targetSize, err := strconv.Atoi(parts[1][1:])
	if err != nil {
		return
	}
	targetSize /= 8

	ops := []FetchOp{}
	buf := []byte{}
	for i := 0; i < len(parts[0]); i++ {
		if parts[0][i] == '(' || parts[0][i] == ')' && len(buf) > 0 {
			size := 8
			if len(ops) == 0 {
				size = targetSize
			}
			op, err := newFetchOp(string(buf), size)
			if err != nil {
				return nil, err
			}
			ops = append(ops, op)
			buf = []byte{}
			continue
		}
		if parts[0][i] != '(' && parts[0][i] != ')' {
			buf = append(buf, parts[0][i])
		}
	}
	if len(buf) > 0 {
		op, err := newFetchOp(string(buf), targetSize)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}

	// reverse
	for i, j := 0, len(ops)-1; i < j; i, j = i+1, j-1 {
		ops[i], ops[j] = ops[j], ops[i]
	}

	return &FetchArg{
		Varname:   varname,
		Statement: statement,
		Size:      targetSize,
		Type:      parts[1],
		Ops:       ops,
	}, nil
}

func (f *FetchArg) CompileBpfInstructions(vacantR10Offset int16, destR6Offset int64) (insts asm.Instructions) {
	for _, op := range f.Ops[:len(f.Ops)-1] {
		is := op.BpfInstructions(vacantR10Offset, asm.R10, int64(vacantR10Offset-op.TargetSize()))
		insts = append(insts, is...)
		vacantR10Offset -= op.TargetSize()
	}
	is := f.Ops[len(f.Ops)-1].BpfInstructions(vacantR10Offset, asm.R6, destR6Offset)
	insts = append(insts, is...)
	return
}

type FetchOp interface {
	BpfInstructions(srcR10Offset int16, dstBase asm.Register, dstOffset int64) asm.Instructions
	TargetSize() int16
}

func newFetchOp(op string, size int) (_ FetchOp, err error) {
	if len(op) != 0 && op[0] == '%' {
		return newReadReg(op[1:])
	}
	offset, err := strconv.ParseInt(op, 10, 64)
	if err != nil {
		return
	}
	return &ReadMemory{
		offset: offset,
		size:   int64(size),
	}, nil
}

var RegisterR8Offsets map[string]int16 = map[string]int16{
	"r15":      0,
	"r14":      8,
	"r13":      16,
	"r12":      24,
	"rbp":      32,
	"rbx":      40,
	"r11":      48,
	"r10":      56,
	"r9":       64,
	"r8":       72,
	"rax":      80,
	"rcx":      88,
	"rdx":      96,
	"rsi":      104,
	"rdi":      112,
	"orig_rax": 120,
	"rip":      128,
	"cs":       136,
	"eflags":   144,
	"rsp":      152,
	"ss":       160,
}

// ReadReg: %rsp
type ReadReg struct {
	register string
}

func newReadReg(reg string) (_ *ReadReg, err error) {
	if _, ok := RegisterR8Offsets[reg]; !ok {
		return nil, fmt.Errorf("unsupported register: %s", reg)
	}
	return &ReadReg{
		register: reg,
	}, nil
}

// BpfInstructions: dstBase[dstOffset] = op.register
func (op *ReadReg) BpfInstructions(_ int16, dstBase asm.Register, dstOffset int64) (insts asm.Instructions) {
	return asm.Instructions{
		// r3 = *(u64 *)(r8 + offsets[op.register])
		{
			OpCode: 121,
			Src:    asm.R8,
			Dst:    asm.R3,
			Offset: RegisterR8Offsets[op.register],
		},
		// *(u64 *)(dstBase + dstOffset) = r3
		{
			OpCode: 123,
			Src:    asm.R3,
			Dst:    dstBase,
			Offset: int16(dstOffset),
		},
	}
}

func (op *ReadReg) TargetSize() int16 {
	return 8
}

// ReadMemory: offset(FETCH):size
type ReadMemory struct {
	offset, size int64
}

// BpfInstructions: bpf_probe_read_user(dstBase+dstOffset, op.size, (void*)R10+srcR10Offset+op.offset)
func (op *ReadMemory) BpfInstructions(srcR10Offset int16, dstBase asm.Register, dstOffset int64) (insts asm.Instructions) {
	return asm.Instructions{
		// r3 = *(u64 *)(r10 + srcR10Offset)
		{
			OpCode: 121,
			Src:    asm.R10,
			Dst:    asm.R3,
			Offset: srcR10Offset,
		},
		// r3 += op.offset
		{
			OpCode:   7,
			Src:      asm.R0,
			Dst:      asm.R3,
			Constant: op.offset,
		},
		// r1 = dstBase
		{
			OpCode: 191,
			Dst:    asm.R1,
			Src:    dstBase,
			Offset: 0,
		},
		// r1 += dstOffset
		{
			OpCode:   7,
			Dst:      asm.R1,
			Src:      asm.R0,
			Constant: dstOffset,
		},
		// r2 = op.size
		{
			OpCode:   183,
			Dst:      asm.R2,
			Src:      asm.R0,
			Constant: op.size,
		},
		// call 112
		{
			OpCode:   133,
			Dst:      asm.R0,
			Src:      asm.R0,
			Constant: 112,
		},
	}
}

func (op *ReadMemory) TargetSize() int16 {
	return int16(op.size)
}

func (f *FetchArg) Sprint(data []uint8) string {
	data = data[:f.Size]
	var value string
	switch f.Type {
	case "u8":
		value = fmt.Sprintf("%d", data[0])
	case "u16":
		value = fmt.Sprintf("%d", binary.LittleEndian.Uint16(data))
	case "u32":
		value = fmt.Sprintf("%d", binary.LittleEndian.Uint32(data))
	case "u64":
		value = fmt.Sprintf("%d", binary.LittleEndian.Uint64(data))
	case "s8":
		value = fmt.Sprintf("%d", int8(data[0]))
	case "s16":
		value = fmt.Sprintf("%d", int16(binary.LittleEndian.Uint16(data)))
	case "s32":
		value = fmt.Sprintf("%d", int32(binary.LittleEndian.Uint32(data)))
	case "s64":
		value = fmt.Sprintf("%d", int64(binary.LittleEndian.Uint64(data)))
	case "f32":
		value = fmt.Sprintf("%f", float32(binary.LittleEndian.Uint32(data)))
	case "f64":
		value = fmt.Sprintf("%f", float64(binary.LittleEndian.Uint64(data)))
	case "c8", "c16", "c32", "c64", "c128", "c256":
		value = string(data[:f.Size])
	}
	return fmt.Sprintf("%s=%s", f.Varname, value)
}
