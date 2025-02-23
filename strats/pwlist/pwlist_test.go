package pwlist

import (
	"reflect"
	"testing"
)

func TestPWListStrategy_GenerateNextStrings(t *testing.T) {
	// Create test passwords
	passwords := []string{"password123", "anotherpass", "secure_pw", "1234567890"}

	// Convert passwords to []interface{} for params
	var pwlistInterface []interface{}
	for _, pw := range passwords {
		pwlistInterface = append(pwlistInterface, pw)
	}

	// Create a Strategy with the passwords
	params := map[string]interface{}{
		"pwlist": pwlistInterface,
	}
	strategy, err := NewStrategy(params)
	if err != nil {
		t.Fatalf("NewStrategy error: %v", err)
	}

	tests := []struct {
		name          string
		startIndex    float64
		n             int
		expected      []string
		expectedIndex float64
	}{
		{
			name:          "read first 2 passwords",
			startIndex:    -1, // -1 indicates no previous progress
			n:             2,
			expected:      []string{"password123", "anotherpass"},
			expectedIndex: 1,
		},
		{
			name:          "read next 2 passwords",
			startIndex:    1,
			n:             2,
			expected:      []string{"secure_pw", "1234567890"},
			expectedIndex: 3,
		},
		{
			name:          "read past end of list",
			startIndex:    3,
			n:             2,
			expected:      []string{},
			expectedIndex: 3,
		},
		{
			name:          "start past end of list",
			startIndex:    4,
			n:             2,
			expected:      []string{},
			expectedIndex: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create progress map
			progress := map[string]interface{}{}
			if tt.startIndex != -1 {
				progress["last_index"] = tt.startIndex
			}

			got, newProgress, err := strategy.GenerateNextStrings(progress, tt.n)

			if err != nil {
				t.Errorf("GenerateNextStrings() unexpected error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("GenerateNextStrings() got = %v, want %v", got, tt.expected)
			}

			var newIndex float64
			if val, ok := newProgress["last_index"]; ok {
				newIndex = val.(float64)
			} else {
				newIndex = -1 // Use -1 to indicate that there is no "last_index"
			}

			if newIndex != tt.expectedIndex {
				t.Errorf("GenerateNextStrings() newIndex = %v, want %v", newIndex, tt.expectedIndex)
			}
		})
	}

	// Test GetTotalStrings
	t.Run("GetTotalStrings", func(t *testing.T) {
		total, err := strategy.GetTotalStrings()
		if err != nil {
			t.Errorf("GetTotalStrings() error = %v", err)
			return
		}
		if total != int64(len(passwords)) {
			t.Errorf("GetTotalStrings() = %v, want %v", total, len(passwords))
		}
	})

	// Test invalid params
	t.Run("NewStrategy with invalid params", func(t *testing.T) {
		invalidParams := map[string]interface{}{
			"pwlist": "not a slice",
		}
		_, err := NewStrategy(invalidParams)
		if err == nil {
			t.Error("NewStrategy() expected error with invalid params, got nil")
		}

		invalidParams = map[string]interface{}{
			"pwlist": []interface{}{123}, // non-string value
		}
		_, err = NewStrategy(invalidParams)
		if err == nil {
			t.Error("NewStrategy() expected error with non-string values, got nil")
		}
	})
}
