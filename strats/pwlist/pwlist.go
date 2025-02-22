package pwlist

import (
	"bufio"
	"errors"
	"os"
)

type PWListStrategy struct {
	pwFilePath   string
	totalStrings int64
}

func NewStrategy(params map[string]interface{}) (*PWListStrategy, error) {
	pwFilePath, ok := params["pwfile"].(string)
	if !ok {
		return nil, errors.New("NewPWListStrategy: pwfile parameter is missing or not a string")
	}

	s := &PWListStrategy{
		pwFilePath: pwFilePath,
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

	// Open and read the password file
	file, err := os.Open(s.pwFilePath)
	if err != nil {
		return nil, nil, errors.New("generateNextStrings: failed to open password file: " + err.Error())
	}
	defer file.Close()

	// Skip to the starting index
	scanner := bufio.NewScanner(file)
	currentIndex := 0
	for currentIndex < startIndex && scanner.Scan() {
		currentIndex++
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, errors.New("generateNextStrings: error reading password file: " + err.Error())
	}

	// Extract the next n passwords
	results := make([]string, 0, n)
	for len(results) < n && scanner.Scan() {
		results = append(results, scanner.Text())
		currentIndex++
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, errors.New("generateNextStrings: error reading password file: " + err.Error())
	}

	// If we got no results and we're not at the start, we've reached the end
	if len(results) == 0 && startIndex > 0 {
		return []string{}, map[string]interface{}{"last_index": float64(currentIndex - 1)}, nil
	}

	// Update progress with last index
	newProgress := map[string]interface{}{
		"last_index": float64(currentIndex - 1),
	}

	return results, newProgress, nil
}

// GetTotalStrings returns the total number of passwords in the file
func (s *PWListStrategy) GetTotalStrings() (int64, error) {
	if s.totalStrings != 0 {
		return s.totalStrings, nil
	}

	file, err := os.Open(s.pwFilePath)
	if err != nil {
		return 0, errors.New("calcTotalStrings: failed to open password file: " + err.Error())
	}
	defer file.Close()

	lineCount := int64(0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineCount++
	}

	if err := scanner.Err(); err != nil {
		return 0, errors.New("calcTotalStrings: error reading password file: " + err.Error())
	}

	s.totalStrings = lineCount
	return lineCount, nil
}
