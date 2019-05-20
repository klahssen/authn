package validators

import (
	"testing"

	"github.com/klahssen/tester"
)

func TestEmail(t *testing.T) {
	te := tester.NewT(t)
	tests := []struct {
		email string
		err   error
	}{
		{"a.b@domain.com", nil},
		{"ab@domain.com", nil},
		{"a.b.c@domain.com", nil},
		{"a.b.c@sub.domain.com", nil},
		{".b@domain.com", errEmailInvalidSyntax},
		{"a.@domain.com", errEmailInvalidSyntax},
		{"a.b.@domain.com", errEmailInvalidSyntax},
		{"a.b@domain.", errEmailInvalidSyntax},
		{"a.b@.com", errEmailInvalidSyntax},
		{"a.b@.", errEmailInvalidSyntax},
	}
	var err error
	for ind, test := range tests {
		err = EmailAddress(test.email)
		te.CheckError(ind, test.err, err)
	}
}
