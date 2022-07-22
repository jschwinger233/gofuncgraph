package symparser

import (
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
	Printer
	Ops []FetchOp
}

func NewFetchArg(varname, statement string) (_ *FetchArg, err error) {
	parts := strings.Split(statement, ":")
	if len(parts) != 2 {
		err = fmt.Errorf("type not found: %s", statement)
		return
	}

	ops := []FetchOp{}
	offsets := []int{}
	i := -1
OUT:
	for {
		bytes := []byte{}
		for {
			i++
			if i == len(parts[0]) {
				break OUT
			}

			if parts[0][i] == '(' {
				offset, err := strconv.Atoi(string(bytes))
				if err != nil {
					return nil, err
				}
				offsets = append(offsets, offset)
				break
			}

			if parts[0][i] == ')' {
				ops = append(ops, newFetchOp(offsets[len(offsets)-1], 8, string(bytes)))
				offsets = offsets[:len(offsets)-1]
				break
			}

			bytes = append(bytes, parts[0][i])
		}
	}
	return &FetchArg{
		Varname:   varname,
		Statement: statement,
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

func newFetchOp(offset, size int, base string) FetchOp {
	if base[0] == '%' {
		return &ReadReg{
			register: base[1:],
		}
	}
	return &ReadMemory{
		offset: int64(offset),
		size:   int64(size),
	}
}

type Printer interface {
	Sprint([]uint8) string
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
