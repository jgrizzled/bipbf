package bipbf

import (
	"sort"
	"testing"
)

// Common test cases
var generateTests = []struct {
	name     string
	minLen   int
	maxLen   int
	charset  string
	expected []string
}{
	{
		name:     "single length, binary charset",
		minLen:   1,
		maxLen:   1,
		charset:  "01",
		expected: []string{"0", "1"},
	},
	{
		name:    "multiple lengths, binary charset",
		minLen:  1,
		maxLen:  2,
		charset: "01",
		expected: []string{
			"0", "1", // length 1
			"00", "01", "10", "11", // length 2
		},
	},
	{
		name:    "multiple lengths, abc charset",
		minLen:  1,
		maxLen:  2,
		charset: "abc",
		expected: []string{
			"a", "b", "c", // length 1
			"aa", "ab", "ac", "ba", "bb", "bc", "ca", "cb", "cc", // length 2
		},
	},
}

// Helper function to run tests for both implementations
func runGenerateTest(t *testing.T, generator func(int, int, string) []string, name string) {
	for _, tt := range generateTests {
		t.Run(tt.name, func(t *testing.T) {
			got := generator(tt.minLen, tt.maxLen, tt.charset)

			// Sort both slices to ensure consistent ordering for comparison
			sort.Strings(got)
			sort.Strings(tt.expected)

			if len(got) != len(tt.expected) {
				t.Errorf("%s() returned %d strings, want %d strings",
					name, len(got), len(tt.expected))
			}

			for i := range tt.expected {
				if i >= len(got) {
					break
				}
				if got[i] != tt.expected[i] {
					t.Errorf("%s()[%d] = %q, want %q",
						name, i, got[i], tt.expected[i])
				}
			}
		})
	}
}
func TestGenerateAllStrings(t *testing.T) {
	runGenerateTest(t, generateAllStrings, "generateAllStrings")
}

var (
	minLen  = 1
	maxLen  = 4
	charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}\\|;:'\",.<>/?`~ "
)

func BenchmarkGenerateAllStrings(b *testing.B) {
	b.ResetTimer()
	generateAllStrings(minLen, maxLen, charset)
}
