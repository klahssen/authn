package apiv1

import (
	"time"

	"github.com/klahssen/authn/pkg/log"
	"github.com/klahssen/authn/pkg/passwords"
	"github.com/klahssen/authn/pkg/validators"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GenNewAccountFunc func(params *AccountParams) (*Account, error)
type ValidateStringFunc func(value string) error
type HashFunc func(pwd []byte) string
type ComparePasswordFunc func(hash string, pwd []byte) bool

type AccountValidator struct {
	generateNew   GenNewAccountFunc
	validateEmail ValidateStringFunc
	validatePwd   ValidateStringFunc
	hashPassword  HashFunc
	authn         ComparePasswordFunc
}

func (av *AccountValidator) SetNewAccountFunc(fn GenNewAccountFunc) {
	av.generateNew = fn
}
func (av *AccountValidator) SetPasswordFunc(fn ValidateStringFunc) {
	av.validatePwd = fn
}
func (av *AccountValidator) SetEmailFunc(fn ValidateStringFunc) {
	av.validateEmail = fn
}
func (av *AccountValidator) SetHashFunc(fn HashFunc) {
	av.hashPassword = fn
}
func (av *AccountValidator) SetAuthnFunc(fn ComparePasswordFunc) {
	av.authn = fn
}

//DefaultValidator returns an AccountValidator with default password and email validation policies
func DefaultValidator() *AccountValidator {
	return &AccountValidator{generateNew: genNewAccount, validateEmail: validateEmail, validatePwd: validatePwd, hashPassword: passwords.HashAndSalt, authn: passwords.CompareHashAndPassword}
}

func genNewAccount(params *AccountParams) (*Account, error) {
	if params == nil {
		return nil, status.Error(codes.InvalidArgument, "empty payload")
	}
	a := &Account{}
	if err := validateEmail(params.Email); err != nil {
		return nil, err
	}
	a.Email = params.Email
	if err := validatePwd(params.Pwd); err != nil {
		return nil, err
	}
	a.Hash = passwords.HashAndSalt([]byte(params.Pwd))
	a.CreatedAt = time.Now().Unix()
	a.UpdatedAt = time.Now().Unix()
	a.Status = AccountStatus_CREATED
	return a, nil
}

//generate a new account from definition (returns grpc errors)
func (a *AccountValidator) New(params *AccountParams) (*Account, error) {
	return a.generateNew(params)
}

//UpdateEmail after format validation
func (av *AccountValidator) UpdateEmail(a *Account, email string) error {
	if err := av.validateEmail(email); err != nil {
		return err
	}
	a.Email = email
	return nil
}

//UpdatePwd after format validation
func (av *AccountValidator) UpdatePwd(a *Account, pwd string) error {
	if err := av.validatePwd(pwd); err != nil {
		return err
	}
	a.Hash = av.hashPassword([]byte(pwd))
	return nil
}

//Authenticate a user and return tokens
func (av *AccountValidator) Authenticate(a *Account, pwd string) bool {
	return av.authn(a.Hash, []byte(pwd))
}

func validatePwd(pwd string) error {
	if err := passwords.ValidateFormat(pwd); err != nil {
		st := status.New(codes.InvalidArgument, "invalid password")
		v := &errdetails.BadRequest_FieldViolation{
			Field:       "pwd",
			Description: err.Error(),
		}
		br := &errdetails.BadRequest{}
		br.FieldViolations = append(br.FieldViolations, v)
		st, err := st.WithDetails(br)
		if err != nil {
			// If this errored, it will always error
			// here, so better panic so we can figure
			// out why than have this silently passing.
			log.Fatal("Unexpected error attaching metadata: %v", err)
		}
		return st.Err()
	}
	return nil
}

func validateEmail(email string) error {
	if err := validators.EmailAddress(email); err != nil {
		st := status.New(codes.InvalidArgument, "invalid email")
		v := &errdetails.BadRequest_FieldViolation{
			Field:       "email",
			Description: err.Error(),
		}
		br := &errdetails.BadRequest{}
		br.FieldViolations = append(br.FieldViolations, v)
		st, err := st.WithDetails(br)
		if err != nil {
			// If this errored, it will always error
			// here, so better panic so we can figure
			// out why than have this silently passing.
			log.Fatal("Unexpected error attaching metadata: %v", err)
		}
		return st.Err()
	}
	return nil
}
