package uprobe

import (
	debugelf "debug/elf"
	"fmt"
	"strings"

	"github.com/jschwinger233/ufuncgraph/elf"
	log "github.com/sirupsen/logrus"
)

type FuncTree struct {
	Name       string
	FpOffset   uint64
	RetOffsets []uint64
	Children   []*FuncTree
	Err        error
}

func (t *FuncTree) Traverse(f func(int, *FuncTree, *FuncTree) bool) {
	t.Visit(0, nil, t, f)
}

func (t *FuncTree) Visit(layer int, parent, self *FuncTree, f func(int, *FuncTree, *FuncTree) bool) {
	cont := f(layer, parent, self)
	if cont {
		for _, tree := range t.Children {
			tree.Visit(layer+1, t, tree, f)
		}
	}
}

func (t *FuncTree) Print(indent int) {
	prefix := strings.Repeat(" ", indent)
	rets := []string{}
	for _, ret := range t.RetOffsets {
		rets = append(rets, fmt.Sprintf("%x", ret))
	}
	if t.Err == nil {
		log.Infof("%s%s: %x %s\n", prefix, t.Name, t.FpOffset, rets)
	} else {
		log.Warnf("%s%s: %s\n", prefix, t.Name, t.Err)
	}
	for _, tree := range t.Children {
		tree.Print(indent + 2)
	}
}

func parseFuncTrees(elf *elf.ELF, wildcards, exWildcards []string, searchDepth int) (trees []*FuncTree, err error) {
	funcnamesMatchedWildcards := func(wildcards []string) (funcnames []string, err error) {
		symbols, _, err := elf.Symbols()
		if err != nil {
			return
		}
		for _, symbol := range symbols {
			if debugelf.ST_TYPE(symbol.Info) == debugelf.STT_FUNC {
				for _, wc := range wildcards {
					if MatchWildcard(wc, symbol.Name) {
						funcnames = append(funcnames, symbol.Name)
						break
					}
				}
			}
		}
		return
	}

	var parseFuncTree func(name string, depth int, ex []string) *FuncTree
	parseFuncTree = func(name string, depth int, ex []string) (tree *FuncTree) {
		tree = &FuncTree{Name: name}
		funcnames, err := elf.FuncCalledBy(name)
		if err != nil {
			tree.Err = err
			return
		}
		tree.FpOffset, tree.Err = elf.FuncFramePointerOffset(name)
		if tree.Err != nil {
			return
		}
		tree.RetOffsets, tree.Err = elf.FuncRetOffsets(name)
		if tree.Err != nil {
			return
		}
		for _, wc := range ex {
			if MatchWildcard(wc, name) {
				tree.Err = fmt.Errorf("excluded by %s", wc)
				break
			}
		}
		if depth == 0 {
			return
		}
		for _, funcname := range funcnames {
			tree.Children = append(tree.Children, parseFuncTree(funcname, depth-1, ex))
		}
		return
	}

	funcnames, err := funcnamesMatchedWildcards(wildcards)
	if err != nil {
		return
	}

	for _, funcname := range funcnames {
		trees = append(trees, parseFuncTree(funcname, searchDepth, exWildcards))
	}
	return
}
