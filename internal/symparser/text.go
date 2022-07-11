package symparser

import (
	"debug/elf"

	"github.com/pkg/errors"
	"golang.org/x/arch/x86/x86asm"
)

func (p *SymParser) findCallingFuncnames(name string) (callees []string, err error) {
	instructions, addr, offset, err := p.findFuncInstructions(name)
	if err != nil {
		return
	}

	for {
		inst, err := x86asm.Decode(instructions, 64)
		if err != nil {
			inst = x86asm.Inst{Len: 1}
			goto next
		}
		if inst.Op == x86asm.CALL && inst.Opcode>>24 == 0xe8 {
			rel, ok := inst.Args[0].(x86asm.Rel)
			if !ok {
				goto next
			}
			callee, err := p.addrToSymbol(uint64(int64(addr) + int64(inst.Len) + int64(rel)))
			if err != nil {
				goto next
			}
			callees = append(callees, callee)
		}

	next:
		offset += uint64(inst.Len)
		addr += uint64(inst.Len)
		instructions = instructions[inst.Len:]
		if len(instructions) == 0 {
			break
		}
	}
	return
}

func (p *SymParser) findFuncInstructions(name string) (instructions []byte, addr, offset uint64, err error) {
	lowpc, highpc, err := p.findFuncRangeByDwarf(name)
	if err != nil {
		if !errors.Is(err, DIENotFoundError) {
			return
		}
		if lowpc, highpc, err = p.findFuncRangeBySymtab(name); err != nil {
			return
		}
	}

	textSection, textBytes, err := p.getTextSection()
	if err != nil {
		return
	}

	return textBytes[lowpc-textSection.Addr : highpc-textSection.Addr], lowpc, lowpc - textSection.Addr + textSection.Offset, nil
}

func (p *SymParser) getTextSection() (textSection *elf.Section, textBytes []byte, err error) {
	if _, ok := p.cache["textSection"]; !ok {
		p.cache["textSection"] = p.elfFile.Section(".text")
	}
	if _, ok := p.cache["textBytes"]; !ok {
		if p.cache["textBytes"], err = p.elfFile.SectionBytes(".text"); err != nil {
			return
		}
	}
	return p.cache["textSection"].(*elf.Section), p.cache["textBytes"].([]byte), err
}

func (p *SymParser) findEntryExitOffsets(name string) (entry uint64, exits []uint64, err error) {
	instructions, _, offset, err := p.findFuncInstructions(name)
	if err != nil {
		return
	}

	bpCnt, foundEntry := 0, false
	for {
		inst, err := x86asm.Decode(instructions, 64)
		if err != nil {
			inst = x86asm.Inst{Len: 1}
			goto next
		}
		for _, a := range inst.Args {
			if a != nil && a.String() == "RBP" {
				bpCnt++
				if bpCnt == 2 {
					entry = offset + uint64(inst.Len)
					foundEntry = true
				}
			}
		}
		if inst.Op == x86asm.RET && foundEntry {
			exits = append(exits, offset)
		}

	next:
		offset += uint64(inst.Len)
		instructions = instructions[inst.Len:]
		if len(instructions) == 0 {
			break
		}
	}
	if entry == 0 {
		err = errors.WithMessage(FramePointerNotFound, name)
		return
	}
	if len(exits) == 0 {
		err = errors.WithMessage(ReturnNotFound, name)
		return
	}
	return
}
