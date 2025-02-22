package wordlist

import (
	"reflect"
	"testing"
)

func TestGenerateNextStrings(t *testing.T) {
	tests := []struct {
		name      string
		wordlist  []string
		length    int
		separator string
		progress  map[string]interface{}
		n         int
		expected  []string
	}{
		{
			name:      "length 1, single word",
			wordlist:  []string{"one"},
			length:    1,
			separator: "",
			progress:  nil,
			n:         10,
			expected:  []string{"one"},
		},
		{
			name:      "length 1, two words",
			wordlist:  []string{"one", "two"},
			length:    1,
			separator: "",
			progress:  nil,
			n:         10,
			expected:  []string{"one", "two"},
		},
		{
			name:      "length 2, two words, no separator",
			wordlist:  []string{"one", "two"},
			length:    2,
			separator: "",
			progress:  nil,
			n:         10,
			expected:  []string{"onetwo", "twoone"},
		},
		{
			name:      "length 2, two words, with separator",
			wordlist:  []string{"one", "two"},
			length:    2,
			separator: "-",
			progress:  nil,
			n:         4,
			expected:  []string{"one-two", "two-one"},
		},
		{
			name:      "length 2, three words, no separator",
			wordlist:  []string{"one", "two", "three"},
			length:    2,
			separator: "",
			progress:  nil,
			n:         10,
			expected:  []string{"onetwo", "onethree", "twoone", "twothree", "threeone", "threetwo"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := &WordlistStrategy{
				wordlist:  tt.wordlist,
				length:    tt.length,
				separator: tt.separator,
			}

			got, _, err := strategy.GenerateNextStrings(tt.progress, tt.n)
			if err != nil {
				t.Errorf("GenerateNextStrings() unexpected error: %v", err)
				return
			}

			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("GenerateNextStrings() got = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetTotalStrings(t *testing.T) {
	tests := []struct {
		name     string
		wordlist []string
		length   int
		expected int64
	}{
		{
			name:     "length 1",
			wordlist: []string{"one", "two", "three"},
			length:   1,
			expected: 3,
		},
		{
			name:     "length 2",
			wordlist: []string{"one", "two"},
			length:   2,
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := &WordlistStrategy{
				wordlist: tt.wordlist,
				length:   tt.length,
			}
			got, err := strategy.GetTotalStrings()
			if err != nil {
				t.Errorf("GetTotalStrings() error = %v", err)
				return
			}
			if got != tt.expected {
				t.Errorf("GetTotalStrings() = %v, want %v", got, tt.expected)
			}

			// Test caching
			got, err = strategy.GetTotalStrings()
			if err != nil {
				t.Errorf("GetTotalStrings() error = %v", err)
				return
			}
			if got != tt.expected {
				t.Errorf("GetTotalStrings() = %v, want %v", got, tt.expected)
			}

		})
	}
}
