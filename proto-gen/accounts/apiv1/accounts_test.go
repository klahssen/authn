package apiv1

import (
	fmt "fmt"
	"reflect"
	"testing"
	"time"

	"github.com/klahssen/authn/pkg/log"
	"github.com/klahssen/authn/pkg/passwords"
	"github.com/klahssen/tester"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func getInvalidEmailErr(err error) error {
	st := status.New(codes.InvalidArgument, "invalid email")
	v := &errdetails.BadRequest_FieldViolation{
		Field:       "email",
		Description: err.Error(),
	}
	br := &errdetails.BadRequest{}
	br.FieldViolations = append(br.FieldViolations, v)
	st, err = st.WithDetails(br)
	if err != nil {
		// If this errored, it will always error
		// here, so better panic so we can figure
		// out why than have this silently passing.
		log.Fatal("Unexpected error attaching metadata: %v", err)
	}
	return st.Err()
}

func getInvalidPwdErr(err error) error {
	st := status.New(codes.InvalidArgument, "invalid password")
	v := &errdetails.BadRequest_FieldViolation{
		Field:       "pwd",
		Description: err.Error(),
	}
	br := &errdetails.BadRequest{}
	br.FieldViolations = append(br.FieldViolations, v)
	st, err = st.WithDetails(br)
	if err != nil {
		// If this errored, it will always error
		// here, so better panic so we can figure
		// out why than have this silently passing.
		log.Fatal("Unexpected error attaching metadata: %v", err)
	}
	return st.Err()
}

func TestValidatePassword(t *testing.T) {
	err := fmt.Errorf("invalid length: min 5, max 64 characters")
	e := getInvalidPwdErr(err)
	tests := []struct {
		pwd string
		err error
	}{
		{"abcdef", nil},
		{"abc", e},
	}
	for ind, test := range tests {
		err = validatePwd(test.pwd)
		if !reflect.DeepEqual(test.err, err) {
			t.Errorf("test %d: expected %v received %v", ind, test.err, err)
		}
	}
}

func TestValidateEmail(t *testing.T) {
	err := fmt.Errorf("invalid syntax")
	e := getInvalidEmailErr(err)
	//te:=test.NewT(t)
	tests := []struct {
		pwd string
		err error
	}{
		{"abc@domain.com", nil},
		{"abc", e},
	}
	for ind, test := range tests {
		err = validateEmail(test.pwd)
		if !reflect.DeepEqual(test.err, err) {
			t.Errorf("test %d: expected %v received %v", ind, test.err, err)
		}
	}
}
func TestNew(t *testing.T) {
	crea := time.Now().Unix()
	upd := time.Now().Unix()
	tests := []struct {
		params *AccountParams
		acc    *Account
		err    error
	}{
		{nil, nil, status.Error(codes.InvalidArgument, "empty payload")},
		{&AccountParams{Email: "abc@domain.com", Pwd: "abcdefghi"}, &Account{Email: "abc@domain.com", Hash: passwords.HashAndSalt([]byte("abcdefghi")), Status: AccountStatus_CREATED}, nil},
		{&AccountParams{Email: "abc@domain.com", Pwd: "abc"}, nil, getInvalidPwdErr(fmt.Errorf("invalid format"))},
		{&AccountParams{Email: "abc@.com", Pwd: "abcdefghi"}, nil, getInvalidEmailErr(fmt.Errorf("invalid format"))},
	}
	av:= DefaultValidator()
	te := tester.NewT(t)
	for ind, test := range tests {
		acc, err := av.New(test.params)
		te.CheckError(ind, test.err, err)
		//te.DeepEqual(ind, "account", test.acc, acc)
		if (test.acc != nil && acc == nil) || (test.acc == nil && acc != nil) {
			t.Errorf("test %d: expected account %v received %v", ind, test.acc, acc)
			continue
		}
		if acc != nil {
			if acc.Email != test.acc.Email {
				t.Errorf("test %d: expected Email %s received %s", ind, test.acc.Email, acc.Email)
			}
			if !passwords.CompareHashAndPassword(acc.Hash, []byte("abcdefghi")) {
				t.Errorf("test %d: password and hash dont match", ind)
			}
			if acc.CreatedAt < crea {
				t.Errorf("test %d: expected CreatedAt >= %d received %d", ind, crea, acc.CreatedAt)
			}
			if acc.UpdatedAt < upd {
				t.Errorf("test %d: expected UpdatedAt >= %d received %d", ind, upd, acc.UpdatedAt)
			}
		}
	}

}
