package jwt

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	pb "github.com/klahssen/authn/proto-gen/accounts/apiv1"
)

type Handler interface {
	Generate(custom *pb.Info, t time.Time, delay time.Duration) (string, error)
	Validate(token string) error
}

var (
	errInvalidClaims            = fmt.Errorf("invalid claims")
	errFailedToGenerateJwtToken = fmt.Errorf("failed to generate token")
)

type AccessToken struct {
	Std    *jwt.StandardClaims `json:"claims"`
	Custom *pb.Info            `json:"account_info"`
}

//Valid to implement jwt.Claims interface. It calls inner Claims.Valid()
func (at *AccessToken) Valid() error {
	return at.Std.Valid()
}

//StdClaimsFunc is a function that validates that a token comes from whitelisted issuer, and has been generated for whitelister audience. subject is the reason of the token (accountID ?)
type StdClaimsFunc func(claims *jwt.StandardClaims) error

//CustomClaimsFunc validates custom claims of the token
type CustomClaimsFunc func(info *pb.Info) error

//SimpleHandler implements Handler interface
type SimpleHandler struct {
	keyPicker  KeyPicker
	keyFunc    jwt.Keyfunc
	stdFunc    StdClaimsFunc
	customFunc CustomClaimsFunc
	validity   time.Duration
	issuer     string
	audience   string
	subject    string
}

//KeyPicker is a function that returns a keyID (string) and signing key ([]byte)
type KeyPicker func() (int, []byte)

//NewHandler returns a new instance of Handler implementing the JWTHandler interface. issuer,audience and subject will be used when generating jwt.StandardClaims
func NewSimpleHandler(issuer, audience, subject string, picker KeyPicker, keyFunc jwt.Keyfunc, stdFunc StdClaimsFunc, customFunc CustomClaimsFunc, validity time.Duration) (*SimpleHandler, error) {
	if picker == nil {
		return nil, fmt.Errorf("key picker is nil")
	}
	if keyFunc == nil {
		return nil, fmt.Errorf("keyFunc is nil")
	}
	if stdFunc == nil {
		return nil, fmt.Errorf("claimsValidator is nil")
	}
	if customFunc == nil {
		return nil, fmt.Errorf("infoValidator is nil")
	}
	if validity < 0 {
		validity *= -1
	}
	return &SimpleHandler{keyPicker: picker, keyFunc: keyFunc, stdFunc: stdFunc, customFunc: customFunc, validity: validity, issuer: issuer, audience: audience, subject: subject}, nil
}

func (h *SimpleHandler) Validate(token string) error {
	c := &AccessToken{}
	_, err := jwt.ParseWithClaims(token, c, h.keyFunc)
	if err != nil {
		return err
	}
	if err = h.stdFunc(c.Std); err != nil {
		return err
	}
	return h.customFunc(c.Custom)
}

//Generate returns a JWT token string: delay is used in not before, t is used for issued at and validity is read from inner value
func (h *SimpleHandler) Generate(custom *pb.Info, t time.Time, delay time.Duration) (string, error) {
	if custom == nil {
		return "", errInvalidClaims
	}
	if delay < 0 {
		delay *= -1
	}
	t.UTC()
	std := &jwt.StandardClaims{Issuer: h.issuer, Audience: h.audience, Subject: h.subject}
	std.IssuedAt = t.Unix()
	std.ExpiresAt = t.Add(h.validity).Unix()
	std.NotBefore = t.Add(delay).Unix()
	at := &AccessToken{Std: std, Custom: custom}
	jwtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, at)
	keyID, signingKey := h.keyPicker()
	jwtoken.Header["kid"] = keyID
	tokenstr, err := jwtoken.SignedString(signingKey)
	if err != nil {
		return "", errFailedToGenerateJwtToken
	}
	return tokenstr, nil
}
