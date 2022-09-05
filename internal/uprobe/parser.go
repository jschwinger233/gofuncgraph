package uprobe

import (
	"fmt"

	"github.com/jschwinger233/gofuncgraph/elf"
)

type ParseOptions struct {
	Wildcards     []string
	ExWildcards   []string
	Fetch         map[string]map[string]string // funcname: varname: expression
	CustomOffsets map[string][]uint64          // funcname: [rel_offset]
	SearchDepth   int
	Backtrace     bool
}

func Parse(elf *elf.ELF, opts *ParseOptions) (uprobes []Uprobe, err error) {
	fetchArgs, err := parseFetchArgs(opts.Fetch)
	if err != nil {
		return
	}

	funcTrees, err := parseFuncTrees(elf, opts.Wildcards, opts.ExWildcards, opts.SearchDepth, opts.CustomOffsets)
	if err != nil {
		return
	}

	visited := map[string]interface{}{}
	for _, tree := range funcTrees {
		tree.Traverse(func(layer int, parent, self *FuncTree) bool {
			if _, ok := visited[self.Name]; ok {
				return false
			}
			visited[self.Name] = nil
			userSpecified := layer == 0
			if self.Err != nil {
				return true
			}
			uprobes = append(uprobes, Uprobe{
				Funcname:      self.Name,
				Location:      AtFramePointer,
				AbsOffset:     self.FpOffset,
				RelOffset:     self.FpOffset - self.EntOffset,
				UserSpecified: userSpecified,
				Backtrace:     userSpecified && opts.Backtrace,
				FetchArgs:     fetchArgs[self.Name],
			})
			for _, relOff := range self.CustomRelOffsets {
				uprobes = append(uprobes, Uprobe{
					Funcname:  self.Name,
					Location:  AtCustom,
					AbsOffset: relOff + self.EntOffset,
					RelOffset: relOff,
					FetchArgs: fetchArgs[fmt.Sprintf("%s+%d", self.Name, relOff)],
				})
			}
			for off, reg := range self.CallRegs {
				arg, err := newFetchArg("__call__", fmt.Sprintf("%%%s:u64", reg))
				if err != nil {
					self.Err = err
					continue
				}
				uprobes = append(uprobes, Uprobe{
					Funcname:  self.Name,
					Location:  AtCustom,
					AbsOffset: off,
					RelOffset: off - self.EntOffset,
					FetchArgs: []*FetchArg{arg},
				})
			}
			for _, off := range self.RetOffsets {
				uprobes = append(uprobes, Uprobe{
					Funcname:  self.Name,
					Location:  AtRet,
					AbsOffset: off,
					RelOffset: off - self.EntOffset,
				})
			}
			return true
		})
		tree.Print()
	}
	return
}
