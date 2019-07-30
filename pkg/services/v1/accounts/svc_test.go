package accounts

import (
	"context"
	"log"
	"math/rand"
	"testing"
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/klahssen/authn/pkg/jwt"
	mock "github.com/klahssen/authn/pkg/services/v1/accounts/mock-repo"
	pb "github.com/klahssen/authn/proto-gen/accounts/apiv1"
	authz "github.com/klahssen/authn/proto-gen/authz/apiv1"
	"github.com/klahssen/tester"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func getMockRepo() pb.AccountRepoServer {
	return mock.NewRepo()
}

type authSvc struct{}

func (a *authSvc) Check(ctx context.Context, params *authz.Req) (*authz.Resp, error) {
	return &authz.Resp{Authorized: true}, nil
}

func getNewService() *Service {
	s, err := New(getMockRepo(), &authSvc{}, pb.DefaultValidator(), getJwtHandler())
	if err != nil {
		log.Fatalf("failed to instantiate service with mock repo: %v", err)
	}
	return s
}

func getJwtHandler() *TokensHandler {
	pf := func() (int, []byte) {
		keys := [][]byte{[]byte("abcdef"), []byte("ghijkl")}
		l := len(keys)
		n := rand.Intn(l)
		if n > l {
			n = 0
		}
		return n, keys[n]
	}
	kf := func(token *jwtgo.Token) (interface{}, error) {
		switch token.Header["kid"] {
		case "001":
			return []byte("abcdef"), nil
		default:
			return []byte("ghijkl"), nil
		}
	}
	sf := func(claims *jwtgo.StandardClaims) error {
		return claims.Valid()
	}
	cf := func(custom *pb.Info) error {
		return nil
	}
	th := &TokensHandler{}
	h, err := jwt.NewSimpleHandler("authn", "authn", "access", pf, kf, sf, cf, time.Minute*10)
	if err != nil {
		log.Fatalf("failed to get new simple access jwt handler: %v", err)
	}
	th.Access = h
	h, err = jwt.NewSimpleHandler("authn", "authn", "refresh", pf, kf, sf, cf, time.Hour*24*3)
	if err != nil {
		log.Fatalf("failed to get new simple refresh jwt handler: %v", err)
	}
	th.Refresh = h
	return th
}
func TestNew(t *testing.T) {
	av := pb.DefaultValidator()
	tests := []struct {
		repo      pb.AccountRepoServer
		validator *pb.AccountValidator
		jwt       *TokensHandler
		err       error
	}{
		{
			nil,
			nil,
			nil,
			status.Error(codes.Internal, "datastore is nil"),
		},
		{
			getMockRepo(),
			nil,
			nil,
			status.Error(codes.Internal, "jwt handler is nil"),
		},
		{
			getMockRepo(),
			av,
			getJwtHandler(),
			nil,
		},
	}
	te := tester.NewT(t)

	for ind, test := range tests {
		_, err := New(test.repo, &authSvc{}, test.validator, test.jwt)
		te.CheckError(ind, test.err, err)
	}
}

func TestCreate(t *testing.T) {
	s := getNewService()
	tests := []struct {
		params *pb.AccountParams
		resp   *pb.AccountID
		err    error
	}{
		{
			params: nil,
			resp:   nil,
			err:    status.Error(codes.InvalidArgument, "empty payload"),
		},
		{
			params: &pb.AccountParams{Email: "account@domain.com", Pwd: "password"},
			resp:   &pb.AccountID{Id: "account@domain.com", Type: pb.IDType_UID},
			err:    nil,
		},
	}
	te := tester.NewT(t)
	for ind, test := range tests {
		resp, err := s.Create(context.Background(), test.params)
		te.CheckError(ind, test.err, err)
		if err != nil {
			continue
		}
		te.DeepEqual(ind, "resp", test.resp, resp)
		_, err = s.GetByUID(context.Background(), &pb.AccountID{Id: test.params.Email, Type: pb.IDType_UID})
		if err != nil {
			t.Errorf("test %d: err after successful create: %v", ind, err)
		}
	}
}

func TestGetByUID(t *testing.T) {
	s := getNewService()
	tests := []struct {
		params *pb.AccountID
		resp   *pb.Account
		err    error
	}{
		{
			params: nil,
			resp:   nil,
			err:    status.Error(codes.InvalidArgument, "empty payload"),
		},
		{
			params: &pb.AccountID{Id: "acct_001@domain.com", Type: pb.IDType_UID},
			resp:   &pb.Account{Uid: "acct_001@domain.com", Hash: "password"},
			err:    nil,
		},
	}
	te := tester.NewT(t)
	for ind, test := range tests {
		_, err := s.GetByUID(context.Background(), test.params)
		te.CheckError(ind, test.err, err)
		if err != nil {
			continue
		}
	}
}
