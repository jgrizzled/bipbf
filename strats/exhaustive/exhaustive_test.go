package exhaustive

import (
	"fmt"
	"testing"
)

func TestGenerateNextStrings(t *testing.T) {
	tests := []struct {
		name         string
		current      string
		charset      string
		n            int
		length       int
		expected     []string
		lastPassword string
		expectError  bool
	}{
		{
			name:         "empty current string, length 1",
			current:      "",
			charset:      "01",
			n:            2,
			length:       1,
			expected:     []string{"0", "1"},
			lastPassword: "1",
			expectError:  false,
		},
		{
			name:         "empty current string, length 2, partial results",
			current:      "",
			charset:      "01",
			n:            3,
			length:       2,
			expected:     []string{"00", "01", "10"},
			lastPassword: "10",
			expectError:  false,
		},
		{
			name:         "resume from middle, length 2",
			current:      "01",
			charset:      "01",
			n:            2,
			length:       2,
			expected:     []string{"10", "11"},
			lastPassword: "11",
			expectError:  false,
		},
		{
			name:         "larger charset",
			current:      "",
			charset:      "abc",
			n:            4,
			length:       2,
			expected:     []string{"aa", "ab", "ac", "ba"},
			lastPassword: "ba",
			expectError:  false,
		},
		{
			name:         "invalid current string",
			current:      "xy",
			charset:      "01",
			n:            3,
			length:       2,
			expected:     nil,
			lastPassword: "",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Construct the params map.
			params := map[string]interface{}{
				"charset": tt.charset,
				"length":  float64(tt.length),
			}

			strategy, err := NewStrategy(params)
			if err != nil {
				t.Fatalf("NewStrategy error: %v", err)
			}

			// Construct the progress map.  If there is no current string,
			// the progress map should be empty.
			progress := map[string]interface{}{}
			if tt.current != "" {
				progress["last_password"] = tt.current
			}

			fmt.Printf("Test: %s\n", tt.name)
			got, newProgress, err := strategy.GenerateNextStrings(progress, tt.n)

			if tt.expectError {
				if err == nil {
					t.Errorf("generateNextNStrings() expected an error, but got none")
				}
				return // Skip further checks if we expect an error
			} else if err != nil {
				t.Errorf("generateNextNStrings() returned an unexpected error: %v", err)
				return // Skip further checks if we got an unexpected error
			}

			if len(got) != len(tt.expected) {
				t.Errorf("generateNextNStrings() returned %d strings, want %d strings",
					len(got), len(tt.expected))
			}

			for i := range tt.expected {
				if i >= len(got) {
					break
				}
				if got[i] != tt.expected[i] {
					t.Errorf("generateNextNStrings()[%d] = %q, want %q",
						i, got[i], tt.expected[i])
				}
			}

			var lastPassword string
			if len(newProgress) > 0 {
				lastPassword = newProgress["last_password"].(string)
			} else {
				lastPassword = ""
			}

			if lastPassword != tt.lastPassword {
				t.Errorf("generateNextNStrings() lastPassword = %q, want %q",
					lastPassword, tt.lastPassword)
			}
			fmt.Printf("-----\n")
		})
	}
}
