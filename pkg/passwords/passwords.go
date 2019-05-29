package passwords

import (
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

var errInvalidFormat = fmt.Errorf("invalid length: min 5, max 64 characters")

func ErrIsInvalidFormat(err error) bool {
	return err == errInvalidFormat
}

//ValidateFormat of a password
func ValidateFormat(pwd string) error {
	l := len(pwd)
	if l < 5 || l > 40 {
		return errInvalidFormat
	}
	return nil
}

//HashAndSalt password
func HashAndSalt(pwd []byte) string {

	// Use GenerateFromPassword to hash & salt pwd.
	// MinCost is just an integer constant provided by the bcrypt
	// package along with DefaultCost & MaxCost.
	// The cost can be any value you want provided it isn't lower
	// than the MinCost (4)
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
	}
	// GenerateFromPassword returns a byte slice so we need to
	// convert the bytes to a string and return it
	return string(hash)
}

//CompareHashAndCleartext returns nil for matching hash and password
func CompareHashAndPassword(hash string, pwd []byte) bool {
	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice
	byteHash := []byte(hash)
	err := bcrypt.CompareHashAndPassword(byteHash, pwd)
	return err == nil
}
