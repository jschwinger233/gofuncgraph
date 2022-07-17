package elf

import (
	"debug/dwarf"
)

func (f *ELF) IterDebugInfo() <-chan *dwarf.Entry {
	ch := make(chan *dwarf.Entry)
	go func() {
		defer close(ch)
		infoReader := f.dwarfData.Reader()
		for {
			entry, err := infoReader.Next()
			if err != nil || entry == nil {
				return
			}
			ch <- entry
		}
	}()
	return ch
}

func (f *ELF) NonInlinedSubprogramDIEs() (dies map[string]*dwarf.Entry, err error) {
	if v, ok := f.cache["subprogramdies"]; ok {
		return v.(map[string]*dwarf.Entry), nil
	}

	_, symnames, err := f.Symbols()
	if err != nil {
		return
	}

	dies = map[string]*dwarf.Entry{}
	for die := range f.IterDebugInfo() {
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
			dies[name] = die
		}
	}
	f.cache["subprogramdies"] = dies
	return dies, nil
}
