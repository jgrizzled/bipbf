package wordlist

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// WordlistStrategy holds the parameters and state for wordlist generation.
type WordlistStrategy struct {
	totalStrings int64
	wordlist     []string
	length       int
	separator    string
}

func NewStrategy(params map[string]interface{}) (*WordlistStrategy, error) {
	wordlist, ok := params["wordlist"].([]interface{})
	if !ok {
		return nil, errors.New("NewStrategy: wordlist is not an array")
	}
	wordlistStr := make([]string, len(wordlist))
	for i, v := range wordlist {
		word, ok := v.(string)
		if !ok {
			return nil, errors.New("NewStrategy: wordlist element is not a string")
		}
		wordlistStr[i] = word
	}

	lengthFloat, ok := params["length"].(float64)
	if !ok {
		return nil, errors.New("NewStrategy: length is not a number")
	}
	length := int(lengthFloat)

	separator, ok := params["separator"].(string)
	if !ok {
		separator = "" // Default to no separator
	}

	s := &WordlistStrategy{
		wordlist:  wordlistStr,
		length:    length,
		separator: separator,
	}

	return s, nil
}

// permutationState is used to store one level of our DFS-like stack for permutation generation.
// Depth: how many words have been chosen so far
// IndicesSoFar: which indices (into the wordlist) we have chosen
// OpIndex: the current "choice index" at this depth
// OpCount: how many possible choices (unused words) at this depth
type permutationState struct {
	Depth        int   `json:"depth"`
	IndicesSoFar []int `json:"indices_so_far"`
	OpIndex      int   `json:"op_index"`
	OpCount      int   `json:"op_count"`
}

// GenerateNextStrings generates the next n strings from the wordlist strategy.
// No word is repeated within the same generated string. The order of words in the
// final string matters, so we're generating permutations (with no repetition)
// of 'length' words from the wordlist.
//
// The 'progress' map is used to store and resume state. If 'done' is set in progress,
// it means we've already exhausted all possible permutations.
//
// The 'progress["stack"]' is a JSON-serialized array of permutationState to
// represent our DFS stack.
func (s *WordlistStrategy) GenerateNextStrings(progress map[string]interface{}, n int) ([]string, map[string]interface{}, error) {
	// If progress is nil, initialize it
	if progress == nil {
		progress = make(map[string]interface{})
	}

	// If we've already marked done, just return empty
	done, _ := progress["done"].(bool)
	if done {
		return []string{}, progress, nil
	}

	// Unmarshal or initialize our stack
	var stack []permutationState
	stackRaw, hasStack := progress["stack"].(string)
	if hasStack && stackRaw != "" {
		if err := json.Unmarshal([]byte(stackRaw), &stack); err != nil {
			return nil, nil, fmt.Errorf("GenerateNextStrings: unable to unmarshal stack from progress: %v", err)
		}
	} else {
		// Initialize the stack
		// At depth = 0, we haven't chosen any words yet.
		// OpCount = number of unused words = len(wordlist).
		stack = []permutationState{
			{
				Depth:        0,
				IndicesSoFar: []int{},
				OpIndex:      0,
				OpCount:      len(s.wordlist),
			},
		}
	}

	results := make([]string, 0, n)

	// Generate up to n strings by advancing the DFS stack
	for i := 0; i < n; i++ {
		nextStr, exhausted, err := s.nextPermutation(&stack)
		if err != nil {
			return results, progress, err
		}
		if exhausted {
			progress["done"] = true
			break
		}
		results = append(results, nextStr)
	}

	// Update the stack in progress
	stackBytes, err := json.Marshal(stack)
	if err != nil {
		return results, progress, fmt.Errorf("GenerateNextStrings: unable to marshal stack: %v", err)
	}
	progress["stack"] = string(stackBytes)

	return results, progress, nil
}

// nextPermutation attempts to advance our DFS-like stack by one step and return
// the next generated permutation string. If we've exhausted all permutations,
// it returns exhausted=true.
func (s *WordlistStrategy) nextPermutation(stack *[]permutationState) (string, bool, error) {
	for {
		// If stack is empty, we have no more permutations to generate
		if len(*stack) == 0 {
			return "", true, nil
		}

		// Look at the top of the stack
		topIndex := len(*stack) - 1
		top := (*stack)[topIndex]

		// If we've reached the desired length, we have a complete permutation
		if top.Depth == s.length {
			// Construct the final string from top.IndicesSoFar
			finalString := s.buildStringFromIndices(top.IndicesSoFar)

			// Pop the stack
			*stack = (*stack)[:topIndex]

			// After popping, increment the parent's OpIndex so it can move to the next choice
			if len(*stack) > 0 {
				parentIndex := len(*stack) - 1
				parent := &((*stack)[parentIndex]) // Get pointer to parent
				parent.OpIndex++
			}

			return finalString, false, nil
		}

		// If we've exhausted all choices at this level, pop and increment parent's OpIndex
		if top.OpIndex >= top.OpCount {
			*stack = (*stack)[:topIndex]
			if len(*stack) == 0 {
				return "", true, nil
			}
			parentIndex := len(*stack) - 1
			parent := &((*stack)[parentIndex]) // Get pointer to parent
			parent.OpIndex++
			continue
		}

		// Otherwise, select the word index that corresponds to top.OpIndex among unused words
		chosenWordIndex, err := s.getUnusedWordIndex(top.IndicesSoFar, top.OpIndex)
		if err != nil {
			return "", false, err
		}

		// Build the new state
		newIndices := append([]int{}, top.IndicesSoFar...)
		newIndices = append(newIndices, chosenWordIndex)

		// Push a new state
		newState := permutationState{
			Depth:        top.Depth + 1,
			IndicesSoFar: newIndices,
			OpIndex:      0,
			OpCount:      len(s.wordlist) - (top.Depth + 1), // Correct OpCount calculation
		}
		*stack = append(*stack, newState)
	}
}

// getUnusedWordIndex finds which word in the wordlist corresponds to the given
// opIndex among the currently unused words. We iterate through the wordlist in
// ascending order, skip the used indices, and pick the opIndex'th unused one.
func (s *WordlistStrategy) getUnusedWordIndex(used []int, opIndex int) (int, error) {
	usedMap := make(map[int]bool, len(used))
	for _, idx := range used {
		usedMap[idx] = true
	}

	count := 0
	for i := 0; i < len(s.wordlist); i++ {
		if !usedMap[i] {
			if count == opIndex {
				return i, nil
			}
			count++
		}
	}

	return -1, fmt.Errorf("getUnusedWordIndex: opIndex %d out of range for unused words", opIndex)
}

// buildStringFromIndices constructs the final string from the given indices in s.wordlist.
func (s *WordlistStrategy) buildStringFromIndices(indices []int) string {
	words := make([]string, len(indices))
	for i, idx := range indices {
		words[i] = s.wordlist[idx]
	}
	if s.separator == "" {
		return strings.Join(words, "")
	}
	return strings.Join(words, s.separator)
}

// GetTotalStrings calculates the total number of distinct permutations we can generate,
// i.e., how many unique strings exist if we pick 'length' distinct words (in order)
// from the wordlist. That is: P(n, k) = n! / (n-k)! if n >= k.
// If n < k, total is 0.
//
// We'll store the result in s.totalStrings so that subsequent calls use the cached value.
func (s *WordlistStrategy) GetTotalStrings() (int64, error) {
	// If we've already calculated, return it
	if s.totalStrings != 0 {
		return s.totalStrings, nil
	}

	n := len(s.wordlist)
	k := s.length
	if k > n {
		s.totalStrings = 0
		return 0, nil
	}

	// Calculate permutations: nPk = n * (n-1) * ... * (n-k+1)
	var total int64 = 1
	for i := 0; i < k; i++ {
		total *= int64(n - i)
		// Optional: we could check for overflow if needed, but typically we just let it wrap
	}

	s.totalStrings = total
	return total, nil
}
