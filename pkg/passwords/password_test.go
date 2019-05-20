package passwords

import (
	"testing"

	"github.com/klahssen/tester"
)

func TestFormat(t *testing.T) {
	te := tester.NewT(t)
	tests := []struct {
		pwd string
		err error
	}{
		{"abcdef", nil},
		{"abc", errInvalidFormat},
		{"AZERTYUIOPQSDFGHJKLMWXCVBNazertyuiopqsdfghjklmwxcvbn123456789012345", errInvalidFormat},
	}
	var err error
	for ind, test := range tests {
		err = ValidateFormat(test.pwd)
		te.CheckError(ind, test.err, err)
	}
}

func TestCompareHash(t *testing.T) {
	tests := []struct {
		toHash    string
		toCompare string
		ok        bool
	}{
		{"abcdef", "abcdef", true},
		{"abcdef", "abcdef ", false},
		{"abcdef", "abcde", false},
		{"abcde", "abcdef", false},
	}
	for ind, test := range tests {
		hash := HashAndSalt([]byte(test.toHash))
		ok := CompareHashAndPassword(hash, []byte(test.toCompare))
		if ok != test.ok {
			t.Errorf("test %d: expected %v received %v", ind, test.ok, ok)
		}
	}
}
