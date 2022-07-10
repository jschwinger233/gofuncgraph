package symparser

import (
	"errors"

	myelf "github.com/jschwinger233/ufuncgraph/elf"
)

type SymParser struct {
	bin     string
	elfFile *myelf.ELFFile

	cache map[string]interface{}
}

func New(bin string) (_ *SymParser, err error) {
	elfFile, err := myelf.New(bin)
	if err != nil {
		return
	}
	return &SymParser{
		bin:     bin,
		elfFile: elfFile,
		cache:   map[string]interface{}{},
	}, nil
}

func (p *SymParser) ParseUprobes(wildcards []string, depth int) (uprobes []Uprobe, err error) {
	funcnames, err := p.findMatchedFunctions(wildcards)
	if err != nil {
		return
	}

	allFuncnameSet := map[string]interface{}{}
	oriFuncnameSet := map[string]interface{}{}
	for _, funcname := range funcnames {
		allFuncnameSet[funcname] = nil
		oriFuncnameSet[funcname] = nil
	}

	searched := map[string]interface{}{}
	toSearch := make([]string, len(oriFuncnameSet))
	copy(toSearch, funcnames)
	for d := 0; d < depth; d++ {
		searching := make([]string, len(toSearch))
		copy(searching, toSearch)
		toSearch = []string{}
		for _, funcname := range searching {
			searched[funcname] = nil
			funcnames, err := p.findCallingFuncnames(funcname)
			if err != nil {
				if errors.Is(err, DIENotFoundError) {
					continue
				}
				return nil, err
			}
			for _, name := range funcnames {
				allFuncnameSet[name] = nil
				if _, ok := searched[name]; !ok {
					toSearch = append(toSearch, name)
				}
			}
		}
	}

	for funcname := range allFuncnameSet {
		entry, exits, err := p.findEntryExitOffsets(funcname)
		if err != nil {
			if errors.Is(err, DIENotFoundError) || errors.Is(err, FramePointerNotFound) || errors.Is(err, ReturnNotFound) {
				continue
			}
			return nil, err
		}
		if entry == 0 || exits[0] == 0 {
			println()
		}
		_, root := oriFuncnameSet[funcname]
		uprobes = append(uprobes, Uprobe{
			Funcname: funcname,
			Location: AtEntry,
			Offset:   entry,
			Root:     root,
		})
		for _, exit := range exits {
			uprobes = append(uprobes, Uprobe{
				Funcname: funcname,
				Location: AtExit,
				Offset:   exit,
			})
		}
	}

	return
}
