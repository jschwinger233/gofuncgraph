package uprobe

import (
	debugelf "debug/elf"
	"fmt"
	"strings"

	"github.com/jschwinger233/ufuncgraph/elf"
	log "github.com/sirupsen/logrus"
)

type FuncTree struct {
	Name             string
	EntOffset        uint64
	FpOffset         uint64
	CustomRelOffsets []uint64
	RetOffsets       []uint64
	Children         []*FuncTree
	CallRegs         map[uint64]string
	Err              error
}

func (t *FuncTree) Traverse(f func(int, *FuncTree, *FuncTree) bool) {
	t.visit(0, nil, t, f)
}

func (t *FuncTree) visit(layer int, parent, self *FuncTree, f func(int, *FuncTree, *FuncTree) bool) {
	cont := f(layer, parent, self)
	if cont {
		for _, tree := range t.Children {
			tree.visit(layer+1, t, tree, f)
		}
	}
}

func (t *FuncTree) Print() {
	t.Traverse(func(layer int, _, self *FuncTree) bool {
		var retpoints, customs, regcalls []string
		indent := strings.Repeat(" ", layer*2)
		for _, ret := range self.RetOffsets {
			retpoints = append(retpoints, fmt.Sprintf("+%x", ret-self.EntOffset))
		}
		for _, cus := range self.CustomRelOffsets {
			customs = append(customs, fmt.Sprintf("+%d", cus))
		}
		for off, regname := range self.CallRegs {
			regcalls = append(regcalls, fmt.Sprintf("+%d:%s", off-self.EntOffset, regname))
		}
		if self.Err == nil {
			log.Infof("%s%s(%x): fp=%x rets=%s customs=%s regcalls=%s\n", indent, self.Name, self.EntOffset, self.FpOffset, retpoints, customs, regcalls)
		} else {
			log.Warnf("%s%s(%x): %s\n", indent, self.Name, self.EntOffset, self.Err)
		}
		return true
	})
}

func parseFuncTrees(elf *elf.ELF, wildcards, exWildcards []string, searchDepth int, customOffsets map[string][]uint64) (trees []*FuncTree, err error) {
	var parseFuncTree func(name string, depth int, ex []string) *FuncTree
	parseFuncTree = func(name string, depth int, ex []string) (tree *FuncTree) {
		tree = &FuncTree{Name: name}
		for _, wc := range ex {
			if MatchWildcard(wc, name) {
				tree.Err = fmt.Errorf("excluded by %s", wc)
				break
			}
		}
		if tree.EntOffset, err = elf.FuncOffset(name); err != nil {
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
		if _, ok := customOffsets[name]; ok {
			tree.CustomRelOffsets = customOffsets[name]
		}
		if depth == 0 {
			return
		}
		funcnames, regs, err := elf.FuncCalledBy(name)
		if err != nil {
			tree.Err = err
			return
		}
		tree.CallRegs = regs
		for _, funcname := range funcnames {
			tree.Children = append(tree.Children, parseFuncTree(funcname, depth-1, ex))
		}
		return
	}

	funcnames := []string{}
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

	for _, funcname := range funcnames {
		trees = append(trees, parseFuncTree(funcname, searchDepth, exWildcards))
	}
	return
}
