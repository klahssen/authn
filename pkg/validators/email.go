package validators

import (
	"fmt"
	"regexp"
)

var emailRegexp = regexp.MustCompile("^[a-zA-Z0-9]{1}[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]{0,61}[a-zA-Z0-9]{1}@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
var errEmailInvalidSyntax = fmt.Errorf("invalid syntax")

//EmailAddress validator
func EmailAddress(email string) error {
	if !emailRegexp.MatchString(email) {
		return errEmailInvalidSyntax
	}
	return nil
}
