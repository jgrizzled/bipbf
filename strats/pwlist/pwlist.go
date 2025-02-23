package pwlist

import (
	"errors"
)

type PWListStrategy struct {
	passwords    []string
	totalStrings int64
}

func NewStrategy(params map[string]interface{}) (*PWListStrategy, error) {
	// Get passwords from params
	pwlistInterface, ok := params["pwlist"].([]interface{})
	if !ok {
		return nil, errors.New("NewPWListStrategy: pwlist parameter is missing or not a []interface{}")
	}

	// Convert []interface{} to []string
	passwords := make([]string, len(pwlistInterface))
	for i, pw := range pwlistInterface {
		str, ok := pw.(string)
		if !ok {
			return nil, errors.New("NewPWListStrategy: password list contains non-string value")
		}
		passwords[i] = str
	}

	s := &PWListStrategy{
		passwords:    passwords,
		totalStrings: int64(len(passwords)),
	}
	return s, nil
}

// GenerateNextStrings generates n strings from the password list starting after the last returned password
func (s *PWListStrategy) GenerateNextStrings(progress map[string]interface{}, n int) ([]string, map[string]interface{}, error) {
	// Get starting index from progress
	startIndex := 0
	if lastIndex, ok := progress["last_index"].(float64); ok {
		startIndex = int(lastIndex) + 1
	}

	// If we're past the end of the list, return empty
	if startIndex >= len(s.passwords) {
		return []string{}, map[string]interface{}{"last_index": float64(len(s.passwords) - 1)}, nil
	}

	// Calculate end index
	endIndex := startIndex + n
	if endIndex > len(s.passwords) {
		endIndex = len(s.passwords)
	}

	// Extract the passwords
	results := s.passwords[startIndex:endIndex]

	// Update progress with last index
	newProgress := map[string]interface{}{
		"last_index": float64(endIndex - 1),
	}

	return results, newProgress, nil
}

// GetTotalStrings returns the total number of passwords
func (s *PWListStrategy) GetTotalStrings() (int64, error) {
	return s.totalStrings, nil
}
