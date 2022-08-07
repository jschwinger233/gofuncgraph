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

func (e *ELF) FuncCalledBy(funcname string) (called []string, err error) {
	insts, addr, _, err := e.FuncInstructions(funcname)
	if err != nil {
		return
	}

	for _, inst := range insts {
		addr += uint64(inst.Len)
		if inst.Op == x86asm.CALL && inst.Opcode>>24 == 0xe8 {
			rel, ok := inst.Args[0].(x86asm.Rel)
			if !ok {
				continue
			}
			syms, off, err := e.ResolveAddress(uint64(int64(addr) + int64(rel)))
			if err != nil || off != 0 {
				continue
			}
			called = append(called, syms[0].Name)
		}
	}
	return
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
	return 0, errors.WithMessage(FramePointerNotFoundErr, name)
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
