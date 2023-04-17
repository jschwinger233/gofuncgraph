package elf

import (
	"github.com/pkg/errors"
	"golang.org/x/arch/x86/x86asm"
)

func (e *ELF) FuncInstructions(name string) (insts []x86asm.Inst, addr, offset uint64, err error) {
	raw, addr, offset, err := e.FuncRawInstructions(name)
	if err != nil {
		return
	}
	return e.ResolveInstructions(raw), addr, offset, nil
}

func (e *ELF) FuncRetOffsets(name string) (offsets []uint64, err error) {
	insts, _, offset, err := e.FuncInstructions(name)
	if err != nil {
		return
	}

	for _, inst := range insts {
		if inst.Op == x86asm.RET {
			offsets = append(offsets, offset)
		}
		offset += uint64(inst.Len)
	}
	return
}

func (e *ELF) FuncFramePointerOffset(name string) (offset uint64, err error) {
	insts, _, offset, err := e.FuncInstructions(name)
	if err != nil {
		return
	}

	bp := 0
	for _, inst := range insts {
		offset += uint64(inst.Len)
		for _, a := range inst.Args {
			if a != nil && a.String() == "RBP" {
				bp++
				if bp == 2 {
					return offset, nil
				}
			}
		}
	}
	return 0, errors.Wrap(FramePointerNotFoundErr, name)
}

func (e *ELF) ResolveInstructions(bytes []byte) (insts []x86asm.Inst) {
	if len(bytes) == 0 {
		return
	}
	for {
		inst, err := x86asm.Decode(bytes, 64)
		if err != nil {
			inst = x86asm.Inst{Len: 1}
		}
		insts = append(insts, inst)
		bytes = bytes[inst.Len:]
		if len(bytes) == 0 {
			break
		}
	}
	return
}
