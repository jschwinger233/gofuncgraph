package uprobe

import (
	"fmt"
	"strings"

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
			retpoints = append(retpoints, fmt.Sprintf("+%d", ret-self.EntOffset))
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
