package variation

import (
	"encoding/json"
	"errors"
	"fmt"
)

// OperationType describes the kind of single edit operation we can perform.
type OperationType int

const (
	OpInsert OperationType = iota
	OpReplace
	OpDelete
)

// Operation represents a single edit step (Insertion, Replacement, or Deletion).
// For insertion or replacement, CharIndex will be used to pick a character from the charset.
// For deletion, CharIndex is ignored.
type Operation struct {
	OpType    OperationType
	Position  int
	CharIndex int // index into the charset, -1 if not applicable
}

// VariationState holds the state for one depth level in our DFS-like approach.
type VariationState struct {
	Depth    int // how many operations have been applied so far
	StrSoFar string
	OpIndex  int // which operation index we're currently exploring at this depth
	OpCount  int // total number of operations possible at this depth
}

// VariationStrategy holds the parameters and state for variation-based password generation.
type VariationStrategy struct {
	basePassword string
	charset      string
	maxOps       int
}

// NewStrategy creates a new VariationStrategy.
func NewStrategy(params map[string]interface{}) (*VariationStrategy, error) {
	basePassword, ok := params["base_password"].(string)
	if !ok {
		return nil, errors.New("NewVariationStrategy: base_password must be a string")
	}

	charset, ok := params["charset"].(string)
	if !ok {
		return nil, errors.New("NewVariationStrategy: charset must be a string")
	}

	opsFloat, ok := params["operations"].(float64)
	if !ok {
		return nil, errors.New("NewVariationStrategy: operations must be a number")
	}
	maxOps := int(opsFloat)

	s := &VariationStrategy{
		basePassword: basePassword,
		charset:      charset,
		maxOps:       maxOps,
	}
	return s, nil
}

// GenerateNextStrings produces up to 'count' new variation passwords.
func (s *VariationStrategy) GenerateNextStrings(progress map[string]interface{}, count int) ([]string, map[string]interface{}, error) {
	// Prepare progress structure if it's empty or nil
	if progress == nil {
		progress = make(map[string]interface{})
	}

	// If done, just return empty
	done, _ := progress["done"].(bool)
	if done {
		return []string{}, progress, nil
	}

	// Unmarshal or initialize our stack
	var stack []VariationState
	stackRaw, hasStack := progress["stack"].(string)
	if hasStack && stackRaw != "" {
		if err := json.Unmarshal([]byte(stackRaw), &stack); err != nil {
			return nil, nil, fmt.Errorf("GenerateNextStrings: unable to unmarshal stack from progress: %v", err)
		}
	} else {
		// Initialize stack
		stack = []VariationState{
			{
				Depth:    0,
				StrSoFar: s.basePassword,
				OpIndex:  0,
				OpCount:  calcOpCount(len(s.basePassword), len(s.charset)),
			},
		}
	}

	results := make([]string, 0, count)

	for i := 0; i < count; i++ {
		nextStr, exhausted, err := s.nextVariation(&stack) // Use method
		if err != nil {
			return results, progress, err
		}
		if exhausted {
			// Mark done and break
			progress["done"] = true
			break
		}
		results = append(results, nextStr)
	}

	// Update stack in progress
	stackBytes, err := json.Marshal(stack)
	if err != nil {
		return results, progress, fmt.Errorf("GenerateNextStrings: unable to marshal stack: %v", err)
	}
	progress["stack"] = string(stackBytes)

	return results, progress, nil
}

// nextVariation advances our DFS-like state machine by one step.  Now a method.
func (s *VariationStrategy) nextVariation(stack *[]VariationState) (string, bool, error) {
	// This loop tries to descend until we reach Depth = maxOps (a valid final string),
	// or backtrack if we exhaust possibilities at a given depth.
	for {
		if len(*stack) == 0 {
			// Exhausted all sequences
			return "", true, nil
		}

		topIndex := len(*stack) - 1
		top := (*stack)[topIndex]

		// If we've reached the desired depth (maxOps), then top.StrSoFar
		// is a valid final string from a completed sequence of edits.
		if top.Depth == s.maxOps {
			// We "yield" this string, then backtrack so next call can find the next one
			finalString := top.StrSoFar

			// Pop
			*stack = (*stack)[:topIndex]
			// Increment parent's OpIndex
			if len(*stack) > 0 {
				parentIndex := len(*stack) - 1
				parent := (*stack)[parentIndex]
				parent.OpIndex++
				(*stack)[parentIndex] = parent
			}
			return finalString, false, nil
		}

		// If we've exhausted all operations at this depth, pop and increment the parent's OpIndex
		if top.OpIndex >= top.OpCount {
			// pop
			*stack = (*stack)[:topIndex]
			if len(*stack) == 0 {
				// no parent => done
				return "", true, nil
			}
			parentIndex := len(*stack) - 1
			parent := (*stack)[parentIndex]
			parent.OpIndex++
			(*stack)[parentIndex] = parent
			// continue the loop, so we re-check the stack top
			continue
		}

		// Otherwise, we select the operation at top.OpIndex, apply it, and descend
		op := getOperation(len(top.StrSoFar), len(s.charset), top.OpIndex)
		newStr := applyOperation(top.StrSoFar, op, s.charset)

		newDepth := top.Depth + 1
		newOpCount := calcOpCount(len(newStr), len(s.charset))

		// push a new state
		newState := VariationState{
			Depth:    newDepth,
			StrSoFar: newStr,
			OpIndex:  0,
			OpCount:  newOpCount,
		}
		*stack = append(*stack, newState)

		// We break here so that on the next iteration, we process the new top of stack.
		// The next iteration will either keep descending or yield if we reached maxOps.
	}
}

// GetTotalStrings calculates the total number of possible strings. Now a method.
func (s *VariationStrategy) GetTotalStrings() (int64, error) {
	// dp[k][L] = number of sequences of length k from an initial string of length L0,
	// that result in a string of length L after k operations. We want sum of dp[n][L].
	dp := make([][]int64, s.maxOps+1)
	for i := 0; i <= s.maxOps; i++ {
		dp[i] = make([]int64, len(s.basePassword)+s.maxOps+1)
	}

	// initial condition
	dp[0][len(s.basePassword)] = 1

	for k := 0; k < s.maxOps; k++ {
		for length := 0; length <= len(s.basePassword)+s.maxOps; length++ {
			if dp[k][length] == 0 {
				continue
			}
			countHere := dp[k][length]

			// insertion: new length is length+1
			// # of insertion ops = (length+1) * charLen
			insOps := int64(length+1) * int64(len(s.charset))
			if length+1 <= len(s.basePassword)+s.maxOps {
				dp[k+1][length+1] += countHere * insOps
			}

			// replacement: new length is length
			// # of replacement ops = length * charLen (only if length > 0)
			if length > 0 {
				repOps := int64(length) * int64(len(s.charset))
				dp[k+1][length] += countHere * repOps
			}

			// deletion: new length is length-1
			// # of deletion ops = length (only if length > 0)
			if length > 0 {
				delOps := int64(length)
				if length-1 >= 0 {
					dp[k+1][length-1] += countHere * delOps
				}
			}
		}
	}

	var total int64
	for length := 0; length <= len(s.basePassword)+s.maxOps; length++ {
		total += dp[s.maxOps][length]
	}
	return total, nil
}

// calcOpCount, getOperation, and applyOperation remain unchanged, but are now used
// as helper functions within the methods of VariationStrategy.

// calcOpCount returns how many possible single operations can be applied to a string of length strLen
// with a given charset of length charsetLen. The operations are:
// 1) Insert any of charsetLen chars into any of (strLen+1) positions => (strLen+1)*charsetLen
// 2) Replace any of charsetLen chars in any of strLen positions => strLen*charsetLen (if strLen > 0)
// 3) Delete any of strLen chars => strLen (if strLen > 0)
func calcOpCount(strLen, charsetLen int) int {
	if strLen == 0 {
		// no replacement or deletion possible
		return (strLen + 1) * charsetLen // just insertion
	}
	return (strLen+1)*charsetLen + strLen*charsetLen + strLen
}

// getOperation returns the operation for the given index (opIndex) in lexicographical
// order among all possible single edits for a string of length strLen.
//
// Ordering is:
//  1. All insertions in ascending (position, then charsetIndex)
//  2. All replacements in ascending (position, then charsetIndex)  [only if strLen > 0]
//  3. All deletions in ascending position [only if strLen > 0]
//
// We do not check bounds here except to assume opIndex is valid.
func getOperation(strLen, charsetLen, opIndex int) Operation {
	// Number of insertion ops
	numInsert := (strLen + 1) * charsetLen

	if opIndex < numInsert {
		// It's an insertion
		pos := opIndex / charsetLen
		charIdx := opIndex % charsetLen
		return Operation{
			OpType:    OpInsert,
			Position:  pos,
			CharIndex: charIdx,
		}
	}
	opIndex -= numInsert

	if strLen == 0 {
		// Should never happen if opIndex is in valid range, but just in case:
		return Operation{OpType: OpInsert, Position: 0, CharIndex: 0}
	}

	// Number of replacement ops
	numReplace := strLen * charsetLen
	if opIndex < numReplace {
		pos := opIndex / charsetLen
		charIdx := opIndex % charsetLen
		return Operation{
			OpType:    OpReplace,
			Position:  pos,
			CharIndex: charIdx,
		}
	}
	opIndex -= numReplace

	// Deletions
	// There are strLen possible deletions
	pos := opIndex
	return Operation{
		OpType:    OpDelete,
		Position:  pos,
		CharIndex: -1,
	}
}

// applyOperation applies a single Operation to a string with the given charset
func applyOperation(strSoFar string, op Operation, charset string) string {
	switch op.OpType {
	case OpInsert:
		// Insert the char at op.Position
		runes := []byte(strSoFar)
		charToInsert := charset[op.CharIndex]
		if op.Position >= len(runes) {
			// append
			return string(append(runes, charToInsert))
		}
		// splice
		newBytes := make([]byte, 0, len(runes)+1)
		newBytes = append(newBytes, runes[:op.Position]...)
		newBytes = append(newBytes, charToInsert)
		newBytes = append(newBytes, runes[op.Position:]...)
		return string(newBytes)

	case OpReplace:
		// Replace the char at op.Position with charset[op.CharIndex]
		if len(strSoFar) == 0 {
			return strSoFar
		}
		runes := []byte(strSoFar)
		runes[op.Position] = charset[op.CharIndex]
		return string(runes)

	case OpDelete:
		// Delete the char at op.Position
		if len(strSoFar) == 0 {
			return strSoFar
		}
		runes := []byte(strSoFar)
		newBytes := make([]byte, 0, len(runes)-1)
		newBytes = append(newBytes, runes[:op.Position]...)
		newBytes = append(newBytes, runes[op.Position+1:]...)
		return string(newBytes)
	}

	return strSoFar
}
