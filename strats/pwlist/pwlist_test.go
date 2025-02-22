package pwlist

import (
	"os"
	"reflect"
	"testing"
)

func TestPWListStrategy_GenerateNextStrings(t *testing.T) {
	// Create a temporary password file.
	tmpfile, err := os.CreateTemp("", "pwlist_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // Clean up the file after the test.

	// Write some passwords to the temporary file.
	passwords := []string{"password123", "anotherpass", "secure_pw", "1234567890"}
	for _, pw := range passwords {
		if _, err := tmpfile.WriteString(pw + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	tmpfile.Close()

	// Create a Strategy with the temporary file.
	params := map[string]interface{}{"pwfile": tmpfile.Name()}
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
		expectError   bool
	}{
		{
			name:          "read first 2 passwords",
			startIndex:    -1, // -1 indicates no previous progress
			n:             2,
			expected:      []string{"password123", "anotherpass"},
			expectedIndex: 1,
			expectError:   false,
		},
		{
			name:          "read next 2 passwords",
			startIndex:    1,
			n:             2,
			expected:      []string{"secure_pw", "1234567890"},
			expectedIndex: 3,
			expectError:   false,
		},
		{
			name:          "read past end of file",
			startIndex:    3,
			n:             2,
			expected:      []string{},
			expectedIndex: 3,
			expectError:   false,
		},
		{
			name:          "start past end of file",
			startIndex:    4,
			n:             2,
			expected:      []string{},
			expectedIndex: 3,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create progress map
			progress := map[string]interface{}{}
			if tt.startIndex != -1 {
				progress["last_index"] = tt.startIndex
			}

			// Create a new strategy for each test case.
			strategy, err := NewStrategy(params)
			if err != nil {
				t.Fatalf("NewStrategy error: %v", err)
			}

			// If the test case is to test for an error opening the file,
			// we change the file path to a non-existent file.
			if tt.expectError {
				strategy.pwFilePath = "non-existent-file"
			}

			got, newProgress, err := strategy.GenerateNextStrings(progress, tt.n)

			if (err != nil) != tt.expectError {
				t.Errorf("GenerateNextStrings() error = %v, expectError %v", err, tt.expectError)
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
		// Create a new strategy for testing GetTotalStrings
		strategy, err = NewStrategy(params)
		if err != nil {
			t.Fatalf("NewStrategy error: %v", err)
		}

		total, err := strategy.GetTotalStrings()
		if err != nil {
			t.Errorf("GetTotalStrings() error = %v", err)
			return
		}
		if total != int64(len(passwords)) {
			t.Errorf("GetTotalStrings() = %v, want %v", total, len(passwords))
		}

		// Test caching behavior of GetTotalStrings
		total, err = strategy.GetTotalStrings()
		if err != nil {
			t.Errorf("GetTotalStrings() error = %v", err)
			return
		}
		if total != int64(len(passwords)) {
			t.Errorf("GetTotalStrings() = %v, want %v", total, len(passwords))
		}
	})

	// Test GetTotalString with error
	t.Run("GetTotalStrings Error", func(t *testing.T) {
		// Create a new strategy for testing GetTotalStrings
		strategy, err = NewStrategy(params)
		if err != nil {
			t.Fatalf("NewStrategy error: %v", err)
		}
		strategy.pwFilePath = "non-existent-file" // Force an error

		_, err = strategy.GetTotalStrings()
		if err == nil {
			t.Errorf("GetTotalStrings() expected error, got nil")
		}
	})
}
