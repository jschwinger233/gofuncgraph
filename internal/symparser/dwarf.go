package symparser

import (
	"debug/dwarf"

	"github.com/pkg/errors"
)

func (p *SymParser) FuncPcRangeInDwarf(funcname string) (lowpc, highpc uint64, err error) {
	dies, err := p.ELF.NonInlinedSubprogramDIEs()
	if err != nil {
		return
	}

	die, ok := dies[funcname]
	if !ok {
		err = errors.WithMessage(DIENotFoundError, funcname)
		return
	}

	lowpc = die.Val(dwarf.AttrLowpc).(uint64)
	switch v := die.Val(dwarf.AttrHighpc).(type) {
	case uint64:
		highpc = v
	case int64:
		highpc = lowpc + uint64(v)
	}
	return
}
