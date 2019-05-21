package accounts

import (
	"context"
	"time"

	cotx "github.com/klahssen/authn/pkg/context"
	"github.com/klahssen/authn/pkg/jwt"
	"github.com/klahssen/authn/pkg/services/v1/actions"
	pb "github.com/klahssen/authn/proto-gen/accounts/apiv1"
	authz "github.com/klahssen/authn/proto-gen/authz/apiv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service struct {
	datastore pb.AccountRepoServer
	authz     authz.AuthzAPIServer
	jwt       *TokensHandler
	validator *pb.AccountValidator
}

//TokensHandler holds a handler for each type of token (Access and Refresh)
type TokensHandler struct {
	Access  jwt.Handler
	Refresh jwt.Handler
}

//func New(datastore pb.AccountRepoServer) (pb.AccountsAPIServer, error) {
func New(datastore pb.AccountRepoServer, authz authz.AuthzAPIServer, validator *pb.AccountValidator, jwt *TokensHandler) (*Service, error) {
	if datastore == nil {
		return nil, status.Error(codes.Internal, "datastore is nil")
	}
	if jwt == nil {
		return nil, status.Error(codes.Internal, "jwt handler is nil")
	}
	if validator == nil {
		validator = pb.DefaultValidator()
	}
	if authz == nil {
		return nil, status.Error(codes.Internal, "authz is nil")
	}
	return &Service{datastore: datastore, jwt: jwt, authz: authz, validator: validator}, nil
}

func (s *Service) Create(ctx context.Context, params *pb.AccountParams) (*pb.AccountID, error) {
	if params == nil {
		return nil, status.Error(codes.InvalidArgument, "empty payload")
	}
	a, err := s.validator.New(params)
	if err != nil {
		return nil, err
	}
	//check for conflict
	//email
	_, err = s.datastore.Get(ctx, &pb.AccountID{Id: a.Email, Type: pb.IDType_EMAIL})
	if err == nil {
		return nil, status.Error(codes.AlreadyExists, "conflicting email")
	}
	//check if parent exists
	if a.ParentAccount != "" {
		_, err = s.datastore.Get(ctx, &pb.AccountID{Id: a.Email, Type: pb.IDType_EMAIL})
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "parent account not found")
		}
	}
	return s.datastore.Insert(ctx, a)
}
func (s *Service) UpdateEmail(ctx context.Context, params *pb.AccountParams) (*pb.AccountID, error) {
	if params == nil {
		return nil, status.Error(codes.InvalidArgument, "empty payload")
	}
	authzParams := &authz.Req{
		Identity: cotx.GetIdentityFromCtx(ctx),
		Action:   actions.AccountsUpdateEmail,
		Path:     []string{"accounts", params.Uid},
	}
	resp, err := s.authz.Check(ctx, authzParams)
	if err != nil {
		return nil, err
	}
	if !resp.Authorized {
		return nil, status.Error(codes.PermissionDenied, "permission denied")
	}
	a, err := s.GetByUID(ctx, &pb.AccountID{Id: params.Uid, Type: pb.IDType_UID})
	if err != nil {
		return nil, err
	}
	err = s.validator.UpdateEmail(a, params.Email)
	if err != nil {
		return nil, err
	}
	a.UpdatedAt = time.Now().Unix()
	return s.datastore.Update(ctx, &pb.PutAccountParams{Uid: params.Uid, Acct: a})
}
func (s *Service) UpdatePassword(ctx context.Context, params *pb.AccountParams) (*pb.AccountID, error) {
	if params == nil {
		return nil, status.Error(codes.InvalidArgument, "empty payload")
	}
	authzParams := &authz.Req{
		Identity:  cotx.GetIdentityFromCtx(ctx),
		Action:    actions.AccountsUpdatePassword,
		Path:      []string{"accounts", params.Uid},
		Namespace: "",
	}
	resp, err := s.authz.Check(ctx, authzParams)
	if err != nil {
		return nil, err
	}
	if !resp.Authorized {
		return nil, status.Error(codes.PermissionDenied, "permission denied")
	}
	a, err := s.GetByUID(ctx, &pb.AccountID{Id: params.Uid, Type: pb.IDType_UID})
	if err != nil {
		return nil, err
	}
	err = s.validator.UpdatePwd(a, params.Email)
	if err != nil {
		return nil, err
	}
	a.UpdatedAt = time.Now().Unix()
	return s.datastore.Update(ctx, &pb.PutAccountParams{Uid: params.Uid, Acct: a})
}
func (s *Service) AddRoles(ctx context.Context, params *pb.AccountPrivileges) (*pb.AccountID, error) {
	if params == nil {
		return nil, status.Error(codes.InvalidArgument, "empty payload")
	}
	authzParams := &authz.Req{
		Identity:  cotx.GetIdentityFromCtx(ctx),
		Action:    actions.AccountsAddRoles,
		Path:      []string{"accounts", params.Uid},
		Namespace: "",
	}
	resp, err := s.authz.Check(ctx, authzParams)
	if err != nil {
		return nil, err
	}
	if !resp.Authorized {
		return nil, status.Error(codes.PermissionDenied, "permission denied")
	}
	a, err := s.GetByUID(ctx, &pb.AccountID{Id: params.Uid, Type: pb.IDType_UID})
	if err != nil {
		return nil, err
	}
	m := map[string]struct{}{}
	for _, role := range a.Roles {
		m[role] = struct{}{}
	}
	for _, role := range params.Roles {
		m[role] = struct{}{}
	}
	res := []string{}
	for r := range m {
		res = append(res, r)
	}
	a.Roles = res
	a.UpdatedAt = time.Now().Unix()
	return s.datastore.Update(ctx, &pb.PutAccountParams{Uid: params.Uid, Acct: a})
}
func (s *Service) RemoveRoles(ctx context.Context, params *pb.AccountPrivileges) (*pb.AccountID, error) {
	if params == nil {
		return nil, status.Error(codes.InvalidArgument, "empty payload")
	}
	authzParams := &authz.Req{
		Identity:  cotx.GetIdentityFromCtx(ctx),
		Action:    "RemoveRoles",
		Path:      []string{"accounts", params.Uid},
		Namespace: "",
	}
	resp, err := s.authz.Check(ctx, authzParams)
	if err != nil {
		return nil, err
	}
	if !resp.Authorized {
		return nil, status.Error(codes.PermissionDenied, "permission denied")
	}
	a, err := s.GetByUID(ctx, &pb.AccountID{Id: params.Uid, Type: pb.IDType_UID})
	if err != nil {
		return nil, err
	}
	m := map[string]struct{}{}
	for _, role := range a.Roles {
		m[role] = struct{}{}
	}
	for _, role := range params.Roles {
		delete(m, role)
	}
	res := []string{}
	for r := range m {
		res = append(res, r)
	}
	a.Roles = res
	a.UpdatedAt = time.Now().Unix()
	return s.datastore.Update(ctx, &pb.PutAccountParams{Uid: params.Uid, Acct: a})
}
func (s *Service) SetRoles(ctx context.Context, params *pb.AccountPrivileges) (*pb.AccountID, error) {
	if params == nil {
		return nil, status.Error(codes.InvalidArgument, "empty payload")
	}
	authzParams := &authz.Req{
		Identity:  cotx.GetIdentityFromCtx(ctx),
		Action:    "SetRoles",
		Path:      []string{"accounts", params.Uid},
		Namespace: "",
	}
	resp, err := s.authz.Check(ctx, authzParams)
	if err != nil {
		return nil, err
	}
	if !resp.Authorized {
		return nil, status.Error(codes.PermissionDenied, "permission denied")
	}
	a, err := s.GetByUID(ctx, &pb.AccountID{Id: params.Uid, Type: pb.IDType_UID})
	if err != nil {
		return nil, err
	}
	m := map[string]struct{}{}
	for _, role := range params.Roles {
		m[role] = struct{}{}
	}
	res := []string{}
	for r := range m {
		res = append(res, r)
	}
	a.Roles = res
	a.UpdatedAt = time.Now().Unix()
	return s.datastore.Update(ctx, &pb.PutAccountParams{Uid: params.Uid, Acct: a})
}
func (s *Service) UpdateStatus(ctx context.Context, params *pb.AccountPrivileges) (*pb.AccountID, error) {
	if params == nil {
		return nil, status.Error(codes.InvalidArgument, "empty payload")
	}
	authzParams := &authz.Req{
		Identity:  cotx.GetIdentityFromCtx(ctx),
		Action:    "UpdateStatus",
		Path:      []string{"accounts", params.Uid},
		Namespace: "",
	}
	resp, err := s.authz.Check(ctx, authzParams)
	if err != nil {
		return nil, err
	}
	if !resp.Authorized {
		return nil, status.Error(codes.PermissionDenied, "permission denied")
	}
	a, err := s.GetByUID(ctx, &pb.AccountID{Id: params.Uid, Type: pb.IDType_UID})
	if err != nil {
		return nil, err
	}
	a.Status = params.Status
	a.UpdatedAt = time.Now().Unix()
	return s.datastore.Update(ctx, &pb.PutAccountParams{Uid: params.Uid, Acct: a})
}
func (s *Service) GetByUID(ctx context.Context, params *pb.AccountID) (*pb.Account, error) {
	if params == nil {
		return nil, status.Error(codes.InvalidArgument, "empty payload")
	}
	authzParams := &authz.Req{
		Identity:  cotx.GetIdentityFromCtx(ctx),
		Action:    "GetByUID",
		Path:      []string{"accounts", params.Id},
		Namespace: "",
	}
	resp, err := s.authz.Check(ctx, authzParams)
	if err != nil {
		return nil, err
	}
	if !resp.Authorized {
		return nil, status.Error(codes.PermissionDenied, "permission denied")
	}
	a, err := s.datastore.Get(ctx, params)
	if err == nil && a != nil {
		a.Uid = params.Id
	}
	return a, err
}

//Authn authenticates a user account from credentials and returns jwt tokens
func (s *Service) Authn(ctx context.Context, params *pb.Credentials) (*pb.JwtAuthTokens, error) {
	if params == nil {
		return nil, status.Error(codes.InvalidArgument, "empty payload")
	}
	a, err := s.GetByUID(ctx, &pb.AccountID{Id: params.Id, Type: pb.IDType_UID})
	if err != nil {
		return nil, err
	}
	if !s.validator.Authenticate(a, params.Pwd) {
		return nil, status.Error(codes.Unauthenticated, "incorrect credentials")
	}
	custom := &pb.Info{Type: "user", Uid: params.Id, Status: a.Status, Roles: a.Roles}
	accessToken, err := s.jwt.Access.Generate(custom, time.Now(), 0)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate access token")
	}
	refreshToken, err := s.jwt.Refresh.Generate(custom, time.Now(), 0)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate refresh token")
	}
	tokens := &pb.JwtAuthTokens{Access: accessToken, Refresh: refreshToken}
	return tokens, nil
}
