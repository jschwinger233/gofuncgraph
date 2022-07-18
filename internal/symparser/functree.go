package symparser

import (
	"fmt"
	"strings"

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
			t.Visit(layer+1, t, tree, f)
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
