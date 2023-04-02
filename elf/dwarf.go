package elf

import (
	"debug/dwarf"
	"io"
	"sort"

	"github.com/pkg/errors"
)

func (e *ELF) IterDebugInfo() <-chan *dwarf.Entry {
	ch := make(chan *dwarf.Entry)
	go func() {
		defer close(ch)
		infoReader := e.dwarfData.Reader()
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

func (e *ELF) NonInlinedSubprogramDIEs() (dies map[string]*dwarf.Entry, err error) {
	if v, ok := e.cache["subprogramdies"]; ok {
		return v.(map[string]*dwarf.Entry), nil
	}

	_, symnames, err := e.Symbols()
	if err != nil {
		return
	}

	dies = map[string]*dwarf.Entry{}
	for die := range e.IterDebugInfo() {
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
	e.cache["subprogramdies"] = dies
	return dies, nil
}

func (e *ELF) FuncPcRangeInDwarf(funcname string) (lowpc, highpc uint64, err error) {
	dies, err := e.NonInlinedSubprogramDIEs()
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

func (e *ELF) LineEntries() (lineEntries []dwarf.LineEntry, err error) {
	if v, ok := e.cache["lineEntries"]; ok {
		return v.([]dwarf.LineEntry), nil
	}
	for die := range e.IterDebugInfo() {
		if die.Tag == dwarf.TagCompileUnit {
			var lineReader *dwarf.LineReader
			lineReader, err = e.dwarfData.LineReader(die)
			if err != nil || lineReader == nil {
				continue
			}

			for {
				entry := dwarf.LineEntry{}
				if err = lineReader.Next(&entry); err != nil {
					if err == io.EOF {
						break
					}
					return
				}
				lineEntries = append(lineEntries, entry)
			}
		}
	}
	sort.Slice(lineEntries, func(i, j int) bool { return lineEntries[i].Address < lineEntries[j].Address })
	e.cache["lineEntries"] = lineEntries
	return
}

func (e *ELF) LineInfoForPc(pc uint64) (filename string, line int, err error) {
	lineEntries, err := e.LineEntries()
	if err != nil {
		return
	}
	idx := sort.Search(len(lineEntries), func(i int) bool { return lineEntries[i].Address >= pc }) - 1
	return lineEntries[idx].File.Name, lineEntries[idx].Line, nil
}

func (e *ELF) FindGoidOffset() (int64, error) {
	foundRuntimeG := false
	for die := range e.IterDebugInfo() {
		switch die.Tag {
		case dwarf.TagStructType:
			v := die.Val(dwarf.AttrName)
			if v == nil {
				continue
			}
			name := v.(string)
			if name != "runtime.g" {
				continue
			}
			foundRuntimeG = true
		case dwarf.TagMember:
			if foundRuntimeG {
				v := die.Val(dwarf.AttrName)
				if v == nil {
					continue
				}
				name := v.(string)
				if name != "goid" {
					continue
				}
				v = die.Val(dwarf.AttrDataMemberLoc)
				if v == nil {
					continue
				}
				return v.(int64), nil
			}
		}
	}
	return 0, errors.New("goid not found")
}
