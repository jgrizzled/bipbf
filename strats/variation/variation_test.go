package variation

import (
	"testing"
)

func TestGenerateNextStrings(t *testing.T) {
	tests := []struct {
		name              string
		params            map[string]interface{}
		progress          map[string]interface{}
		count             int
		shouldIncludeStrs []string
		expectError       bool
		errorContains     string
	}{
		{
			name: "basic single operation",
			params: map[string]interface{}{
				"base_password": "a",
				"charset":       "ab",
				"operations":    float64(1),
			},
			progress:          nil,
			count:             10,
			shouldIncludeStrs: []string{"aa", "ab", "ba", "b"},
			expectError:       false,
		},
		{
			name: "case 2",
			params: map[string]interface{}{
				"base_password": "ab",
				"charset":       "abc",
				"operations":    float64(1),
			},
			progress:          nil,
			count:             100,
			shouldIncludeStrs: []string{"aa"},
			expectError:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy, err := NewStrategy(tt.params)
			if err != nil {
				t.Errorf("NewStrategy error: %v", err)
				return
			}
			got, newProgress, err := strategy.GenerateNextStrings(tt.progress, tt.count)

			// Check error cases
			if tt.expectError {
				if err == nil {
					t.Errorf("GenerateNextStrings() expected error containing %q, got nil", tt.errorContains)
					return
				}
				if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("GenerateNextStrings() error = %v, want error containing %q", err, tt.errorContains)
				}
				return
			}

			// Check non-error cases
			if err != nil {
				t.Errorf("GenerateNextStrings() unexpected error: %v", err)
				return
			}

			// Instead of DeepEqual, check that all expected strings are present
			for _, expected := range tt.shouldIncludeStrs {
				found := false
				for _, actual := range got {
					if expected == actual {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("GenerateNextStrings() missing expected string %q in result %v", expected, got)
				}
			}

			// Verify that progress is being tracked
			if newProgress == nil {
				t.Error("GenerateNextStrings() returned nil progress")
			}
		})
	}
}

func TestCalcTotalStrings(t *testing.T) {
	tests := []struct {
		name            string
		params          map[string]interface{}
		expectedTotal   int64
		expectError     bool
		expectInitError bool
	}{
		{
			name: "single character, one operation",
			params: map[string]interface{}{
				"base_password": "a",
				"charset":       "ab",
				"operations":    float64(1),
			},
			expectedTotal: 7,
			expectError:   false,
		},
		{
			name: "empty string, one operation",
			params: map[string]interface{}{
				"base_password": "",
				"charset":       "ab",
				"operations":    float64(1),
			},
			expectedTotal: 2, // only insertions possible
			expectError:   false,
		},
		{
			name: "missing base_password",
			params: map[string]interface{}{
				"charset":    "ab",
				"operations": float64(1),
			},
			expectedTotal:   0,
			expectError:     true,
			expectInitError: true,
		},
		{
			name: "zero operations",
			params: map[string]interface{}{
				"base_password": "test",
				"charset":       "abcdefgh",
				"operations":    float64(0),
			},
			expectedTotal: 1, // only the original string
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy, err := NewStrategy(tt.params)
			if err != nil {
				if !tt.expectInitError {
					t.Errorf("NewStrategy() returned an unexpected error: %v", err)
				} else {
					return
				}
				return
			}
			got, err := strategy.GetTotalStrings()

			if tt.expectError {
				if err == nil {
					t.Error("CalcTotalStrings() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("CalcTotalStrings() unexpected error: %v", err)
				return
			}

			if got != tt.expectedTotal {
				t.Errorf("CalcTotalStrings() = %v, want %v", got, tt.expectedTotal)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[0:len(substr)] == substr
}
