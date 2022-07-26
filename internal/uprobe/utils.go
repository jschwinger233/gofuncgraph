package uprobe

func MatchWildcard(pattern, str string) bool {
	if len(pattern) == 0 && len(str) == 0 {
		return true
	}
	if len(pattern) == 0 {
		return false
	}
	if len(str) == 0 {
		for _, p := range pattern {
			if p != '*' {
				return false
			}
		}
		return true
	}

	if pattern[0] == '*' {
		for i := 0; i <= len(str); i++ {
			if MatchWildcard(pattern[1:], str[i:]) {
				return true
			}
		}
		return false
	}

	return pattern[0] == str[0] && MatchWildcard(pattern[1:], str[1:])
}
