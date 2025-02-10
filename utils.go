package bipbf

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
