package bipbf

import (
	"strings"
)

// generateNextNStrings generates n strings starting from the given current string
// using the provided charset. It returns the generated strings and the next string
// to resume from. If there are no more strings possible, the second return value
// will be an empty string.
func generateNextNStrings(current string, charset string, n int, length int) ([]string, string) {
	if current == "" {
		current = strings.Repeat(string(charset[0]), length)
	}

	results := make([]string, 0, n)

	// Initialize indices array based on current string
	indices := make([]int, length)
	for i := 0; i < length; i++ {
		idx := indexOf(current[i], charset)
		if idx == -1 {
			return nil, ""
		}
		indices[i] = idx
	}

	// Generate n strings or until we exhaust all possibilities
	for count := 0; count < n; count++ {
		// Build current string from indices
		nextStr := make([]byte, length)
		for i := 0; i < length; i++ {
			nextStr[i] = charset[indices[i]]
		}
		results = append(results, string(nextStr))

		// Update indices for next combination
		pos := length - 1
		for pos >= 0 {
			indices[pos]++
			if indices[pos] < len(charset) {
				break
			}
			indices[pos] = 0
			pos--
		}

		// If we've wrapped around at all positions, we're done
		if pos < 0 {
			return results, ""
		}
	}

	// Build the next string to resume from
	nextToResume := make([]byte, length)
	for i := 0; i < length; i++ {
		nextToResume[i] = charset[indices[i]]
	}

	return results, string(nextToResume)
}

// generateAllStrings generates all possible strings with lengths from minLength to maxLength
// using the given charset. It returns a slice containing all generated strings.
// Used for testing/benchmarking
func generateAllStrings(minLength, maxLength int, charset string) []string {
	// Handle invalid input
	if minLength < 1 || maxLength < minLength || len(charset) == 0 {
		return nil
	}

	results := make([]string, 0)

	// For each length in the range
	for length := minLength; length <= maxLength; length++ {
		current := "" // Start with empty string to generate first combination

		// Generate strings in batches
		for {
			strings, nextStart := generateNextNStrings(current, charset, 1000000, length)
			results = append(results, strings...)

			if nextStart == "" {
				break
			}
			current = nextStart
		}
	}

	return results
}
