package symparser

import (
	"errors"

	myelf "github.com/jschwinger233/ufuncgraph/elf"
	log "github.com/sirupsen/logrus"
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

func (p *SymParser) ParseUprobes(wildcards []string, depth int, golang bool) (uprobes []Uprobe, err error) {
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
				if errors.Is(err, DIENotFoundError) || errors.Is(err, SymbolNotFoundError) {
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

	if golang {
		for funcname := range allFuncnameSet {
			entry, exits, err := p.findEntryExitOffsets(funcname)
			if err != nil {
				log.Warnf("failed to get uprobe: %s", err)
				continue
			}
			_, root := oriFuncnameSet[funcname]
			uprobes = append(uprobes, Uprobe{
				Funcname: funcname,
				Location: AtFramePointer,
				Offset:   entry,
				Root:     root,
			})
			log.Debugf("add uprobe %s entry: %d", funcname, entry)
			for _, exit := range exits {
				uprobes = append(uprobes, Uprobe{
					Funcname: funcname,
					Location: AtRet,
					Offset:   exit,
				})
			}
			log.Debugf("add uprobe %s exits: %v", funcname, exits)
		}
	} else {
		for funcname := range allFuncnameSet {
			offset, err := p.findSymbolOffset(funcname)
			if err != nil {
				log.Warnf("failed to get uprobe: %s", err)
				continue
			}
			_, root := oriFuncnameSet[funcname]
			uprobes = append(uprobes, Uprobe{
				Funcname: funcname,
				Location: AtEntry,
				Offset:   offset,
				Root:     root,
			})
		}
	}

	return
}
