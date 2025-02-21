package exhaustive

import (
	"errors"
	"fmt"
)

// initializeIndices initializes the indices slice based on the current string.
func initializeIndices(current string, charset string, length int) ([]int, error) {
	indices := make([]int, length)
	if len(current) == 0 {
		return indices, nil // Return all zeros
	}
	for i := 0; i < len(current); i++ {
		idx := indexOf(current[i], charset)
		if idx == -1 {
			return nil, fmt.Errorf("initializeIndices: invalid character %q in current string", current[i])
		}
		indices[i] = idx
	}
	return indices, nil
}

// incrementIndices increments the indices, handling carry-over.
// Returns true if increment was successful, false if all combinations are exhausted.
func incrementIndices(indices []int, charset string) bool {
	pos := len(indices) - 1
	for pos >= 0 {
		indices[pos]++
		if indices[pos] < len(charset) {
			return true // Increment successful
		}
		indices[pos] = 0
		pos--
	}
	return false // All combinations exhausted
}

// buildStringFromIndices builds a string from the given indices and charset.
func buildStringFromIndices(indices []int, charset string) string {
	nextStr := make([]byte, len(indices))
	for i := 0; i < len(indices); i++ {
		nextStr[i] = charset[indices[i]]
	}
	return string(nextStr)
}

// GenerateNextStrings generates n strings starting from the given current string
// using the provided charset.
func GenerateNextStrings(params map[string]interface{}, progress map[string]interface{}, n int) ([]string, map[string]interface{}, error) {
	charset, ok := params["charset"].(string)
	if !ok {
		return nil, nil, errors.New("generateNextNStrings: charset is not a string")
	}
	lengthFloat, ok := params["length"].(float64)
	if !ok {
		return nil, nil, errors.New("generateNextNStrings: length is not a number")
	}
	length := int(lengthFloat)

	current, hasCurrent := progress["last_password"].(string)

	indices, err := initializeIndices(current, charset, length)
	if err != nil {
		return nil, nil, err
	}

	if hasCurrent && len(current) > 0 {
		if !incrementIndices(indices, charset) {
			return []string{}, map[string]interface{}{}, nil
		}
	}

	results := make([]string, 0, n)
	for count := 0; count < n; count++ {
		results = append(results, buildStringFromIndices(indices, charset))
		if !incrementIndices(indices, charset) {
			break
		}
	}

	newProgress := map[string]interface{}{"last_password": results[len(results)-1]}
	return results, newProgress, nil
}

// indexOf returns the index of character 'b' in the string 'charset'.
func indexOf(b byte, charset string) int {
	for i := 0; i < len(charset); i++ {
		if charset[i] == b {
			return i
		}
	}
	return -1
}

// calcTotalPossibilities calculates the total number of possible passwords
// for the given exhaustive parameters
func CalcTotalPossibilities(params map[string]interface{}) (int64, error) {
	charset, ok := params["charset"].(string)
	if !ok {
		return 0, errors.New("calcTotalPossibilities: charset is not a string")
	}
	lengthFloat, ok := params["length"].(float64) // JSON numbers are floats
	if !ok {
		return 0, errors.New("calcTotalPossibilities: length is not a number")
	}
	length := int(lengthFloat)

	base := len(charset)
	totalCombos := int64(1)
	for i := 0; i < length; i++ {
		totalCombos *= int64(base)
	}
	return totalCombos, nil
}
