package naive

// indexOf returns the index of character 'b' in the string 'charset',
// or -1 if 'b' is not found.
func indexOf(b byte, charset string) int {
	for i := 0; i < len(charset); i++ {
		if charset[i] == b {
			return i
		}
	}
	return -1
}

// IndexToString converts a lexicographic index to a string of fixed length
// using the characters in charset. If index is out of range, it returns an empty string.
func indexToString(index int, length int, charset string) string {
	base := len(charset)
	if base == 0 || length < 0 {
		return ""
	}

	// Calculate total number of combinations = base^length.
	total := 1
	for i := 0; i < length; i++ {
		total *= base
	}
	if index < 0 || index >= total {
		return ""
	}

	// Build the string from rightmost to leftmost symbol.
	result := make([]byte, length)
	for i := length - 1; i >= 0; i-- {
		result[i] = charset[index%base]
		index /= base
	}
	return string(result)
}

// StringToIndex converts a string to its lexicographic index based on the given charset.
// It returns -1 if the string length does not match or if any character is not found within the charset.
func stringToIndex(s string, length int, charset string) int {
	if len(s) != length {
		return -1
	}
	base := len(charset)
	index := 0
	for i := 0; i < len(s); i++ {
		pos := indexOf(s[i], charset)
		if pos == -1 {
			return -1
		}
		index = index*base + pos
	}
	return index
}
