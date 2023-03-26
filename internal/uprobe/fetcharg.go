package uprobe

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

type FetchArg struct {
	Varname   string
	Statement string
	Type      string
	Size      int
	Rules     []*ArgRule
}

type ArgLocation int

const (
	Register ArgLocation = iota
	Stack
)

type ArgRule struct {
	From     ArgLocation
	Register string
	Offset   int64
}

func parseFetchArgs(fetch map[string]map[string]string) (fetchArgs map[string][]*FetchArg, err error) {
	fetchArgs = map[string][]*FetchArg{}
	for funcname, fet := range fetch {
		for name, statement := range fet {
			fa, err := newFetchArg(name, statement)
			if err != nil {
				return nil, err
			}
			fetchArgs[funcname] = append(fetchArgs[funcname], fa)
		}
	}
	return
}

func newFetchArg(varname, statement string) (_ *FetchArg, err error) {
	parts := strings.Split(statement, ":")
	if len(parts) != 2 {
		err = fmt.Errorf("type not found: %s", statement)
		return
	}
	switch parts[1][0] {
	case 'u', 's':
		switch parts[1][1:] {
		case "8", "16", "32", "64":
			break
		default:
			err = fmt.Errorf("only support 8/16/32/64 bits for u/s type: %s", parts[1])
			return
		}

	case 'c':
		switch parts[1][1:] {
		case "8", "16", "32", "64", "128", "256", "512":
			break
		default:
			err = fmt.Errorf("only support 8/16/32/64/128/256/512 bits for c type: %s", parts[1])
			return
		}

	default:
		err = fmt.Errorf("only support u/s/c type: %s", parts[1])
		return
	}

	targetSize, err := strconv.Atoi(parts[1][1:])
	if err != nil {
		return
	}
	targetSize /= 8

	rules := []*ArgRule{}
	buf := []byte{}
	for i := 0; i < len(parts[0]); i++ {
		if parts[0][i] == '(' || parts[0][i] == ')' && len(buf) > 0 {
			op, err := newFetchOp(string(buf))
			if err != nil {
				return nil, err
			}
			rules = append(rules, op)
			buf = []byte{}
			continue
		}
		if parts[0][i] != '(' && parts[0][i] != ')' {
			buf = append(buf, parts[0][i])
		}
	}
	if len(buf) > 0 {
		op, err := newFetchOp(string(buf))
		if err != nil {
			return nil, err
		}
		rules = append(rules, op)
	}

	// reverse
	for i, j := 0, len(rules)-1; i < j; i, j = i+1, j-1 {
		rules[i], rules[j] = rules[j], rules[i]
	}

	return &FetchArg{
		Varname:   varname,
		Statement: statement,
		Size:      targetSize,
		Type:      parts[1],
		Rules:     rules,
	}, nil
}

func newFetchOp(op string) (_ *ArgRule, err error) {
	if len(op) != 0 && op[0] == '%' {
		switch op[1:] {
		case "ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15":
			break
		default:
			return nil, fmt.Errorf("unknown register: %s", op[1:])
		}
		return &ArgRule{
			From:     Register,
			Register: op[1:],
		}, nil
	}
	offset, err := strconv.ParseInt(op, 10, 64)
	if err != nil {
		return
	}
	return &ArgRule{
		From:   Stack,
		Offset: offset,
	}, nil
}

func (f *FetchArg) SprintValue(data []uint8) (value string) {
	data = data[:f.Size]
	switch f.Type {
	case "u8":
		value = fmt.Sprintf("%d", data[0])
	case "u16":
		value = fmt.Sprintf("%d", binary.LittleEndian.Uint16(data))
	case "u32":
		value = fmt.Sprintf("%d", binary.LittleEndian.Uint32(data))
	case "u64":
		value = fmt.Sprintf("%d", binary.LittleEndian.Uint64(data))
	case "s8":
		value = fmt.Sprintf("%d", int8(data[0]))
	case "s16":
		value = fmt.Sprintf("%d", int16(binary.LittleEndian.Uint16(data)))
	case "s32":
		value = fmt.Sprintf("%d", int32(binary.LittleEndian.Uint32(data)))
	case "s64":
		value = fmt.Sprintf("%d", int64(binary.LittleEndian.Uint64(data)))
	case "f32":
		value = fmt.Sprintf("%f", float32(binary.LittleEndian.Uint32(data)))
	case "f64":
		value = fmt.Sprintf("%f", float64(binary.LittleEndian.Uint64(data)))
	case "c8", "c16", "c32", "c64", "c128", "c256", "c512":
		value = string(data[:f.Size])
	}
	return
}
