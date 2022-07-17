package symparser

import (
	"github.com/jschwinger233/ufuncgraph/elf"
	log "github.com/sirupsen/logrus"
)

type SymParser struct {
	bin string
	*elf.ELF

	cache map[string]interface{}
}

func New(bin string) (_ *SymParser, err error) {
	elf, err := elf.New(bin)
	if err != nil {
		return
	}
	return &SymParser{
		bin:   bin,
		ELF:   elf,
		cache: map[string]interface{}{},
	}, nil
}

func (p *SymParser) ParseUprobes(wildcards []string, depth int) (uprobes []Uprobe, err error) {
	funcnames, err := p.FuncnamesMatchedWildcards(wildcards)
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
			funcnames, err := p.FuncCalledBy(funcname)
			if err != nil {
				continue
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
		fpOffset, err := p.FuncFramePointerOffset(funcname)
		if err != nil {
			log.Warnf("failed to get entpoint: %s", err)
			continue
		}
		retOffsets, err := p.FuncRetOffsets(funcname)
		if err != nil {
			log.Warnf("failed to get retpoints: %s", err)
			continue
		}
		_, userSpecified := oriFuncnameSet[funcname]
		uprobes = append(uprobes, Uprobe{
			Funcname:      funcname,
			Location:      AtFramePointer,
			Offset:        fpOffset,
			UserSpecified: userSpecified,
		})
		log.Debugf("added uprobe %s at framepointor: %d", funcname, fpOffset)
		for _, off := range retOffsets {
			uprobes = append(uprobes, Uprobe{
				Funcname: funcname,
				Location: AtRet,
				Offset:   off,
			})
		}
		log.Debugf("added uprobe %s at ret: %v", funcname, retOffsets)
	}

	return
}
