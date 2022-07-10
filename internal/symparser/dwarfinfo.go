package symparser

import (
	"debug/dwarf"

	"github.com/pkg/errors"
)

func (p *SymParser) getValidDwarfInfo() (dwarfinfo map[string]*dwarf.Entry, err error) {
	_, symnames, err := p.getSymtab()
	if err != nil {
		return
	}
	if _, ok := p.cache["dwarfinfo"]; !ok {
		dwarfinfo := map[string]*dwarf.Entry{}
		for die := range p.elfFile.IterDebugInfo() {
			if die.Tag == dwarf.TagSubprogram {
				v := die.Val(dwarf.AttrName)
				if v == nil {
					continue
				}
				name := v.(string)
				v = die.Val(dwarf.AttrLowpc)
				if v == nil {
					continue
				}
				lowpc := v.(uint64)
				v = die.Val(dwarf.AttrHighpc)
				if v == nil {
					continue
				}

				sym, ok := symnames[name]
				if !ok {
					continue
				}
				if sym.Value != lowpc {
					continue
				}
				dwarfinfo[name] = die
			}
		}
		p.cache["dwarfinfo"] = dwarfinfo
	}
	return p.cache["dwarfinfo"].(map[string]*dwarf.Entry), nil
}

func (p *SymParser) getValidDIE(funcname string) (_ *dwarf.Entry, err error) {
	dwarfinfo, err := p.getValidDwarfInfo()
	if err != nil {
		return
	}
	die, ok := dwarfinfo[funcname]
	if !ok {
		return nil, errors.WithMessage(DIENotFoundError, funcname)
	}
	return die, nil
}
