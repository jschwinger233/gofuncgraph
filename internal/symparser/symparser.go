package symparser

import (
	"fmt"

	"github.com/jschwinger233/ufuncgraph/elf"
	"github.com/jschwinger233/ufuncgraph/utils"
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

func (p *SymParser) ParseUprobes(in, ex []string, fetch map[string]map[string]string, depth int, backtrace bool) (uprobes []Uprobe, err error) {
	fetchArgs := map[string][]*FetchArg{}
	for funcname, fet := range fetch {
		for name, state := range fet {
			fa, err := NewFetchArg(name, state)
			if err != nil {
				return nil, err
			}
			fetchArgs[funcname] = append(fetchArgs[funcname], fa)
		}
	}
	funcnames, err := p.FuncnamesMatchedWildcards(in)
	if err != nil {
		return
	}

	trees := []*FuncTree{}
	for _, funcname := range funcnames {
		trees = append(trees, p.ParseFuncTree(funcname, depth, ex))
	}

	visited := map[string]interface{}{}
	for _, tree := range trees {
		tree.Print(0)
		tree.Traverse(func(layer int, parent, self *FuncTree) bool {
			if _, ok := visited[self.Name]; ok {
				return false
			}
			visited[self.Name] = nil
			if self.Err != nil {
				return true
			}

			userSpecified := layer == 0
			uprobes = append(uprobes, Uprobe{
				Funcname:      self.Name,
				Location:      AtFramePointer,
				Offset:        self.FpOffset,
				UserSpecified: userSpecified,
				Backtrace:     userSpecified && backtrace,
				FetchArgs:     fetchArgs[self.Name],
			})
			for _, off := range self.RetOffsets {
				uprobes = append(uprobes, Uprobe{
					Funcname: self.Name,
					Location: AtRet,
					Offset:   off,
				})
			}
			return true
		})
	}

	return
}

func (p *SymParser) ParseFuncTree(name string, depth int, ex []string) (tree *FuncTree) {
	tree = &FuncTree{Name: name}
	funcnames, err := p.FuncCalledBy(name)
	if err != nil {
		tree.Err = err
		return
	}
	tree.FpOffset, tree.Err = p.FuncFramePointerOffset(name)
	if tree.Err != nil {
		return
	}
	tree.RetOffsets, tree.Err = p.FuncRetOffsets(name)
	if tree.Err != nil {
		return
	}
	for _, wc := range ex {
		if utils.MatchWildcard(wc, name) {
			tree.Err = fmt.Errorf("excluded by %s", wc)
			break
		}
	}
	if depth == 0 {
		return
	}
	for _, funcname := range funcnames {
		tree.Children = append(tree.Children, p.ParseFuncTree(funcname, depth-1, ex))
	}
	return
}
