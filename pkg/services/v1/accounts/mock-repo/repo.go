package repo

import (
	"context"
	"fmt"
	"time"

	"github.com/klahssen/authn/pkg/passwords"
	pb "github.com/klahssen/authn/proto-gen/accounts/apiv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Repo struct {
	data map[string]*pb.Account
}

func NewRepo() *Repo {
	r := &Repo{}
	r.data = map[string]*pb.Account{
		"acct_001@domain.com": &pb.Account{
			Uid:       "acct_001@domain.com",
			Email:     "acct_001@domain.com",
			Hash:      passwords.HashAndSalt([]byte("password_001")),
			CreatedAt: time.Unix(0, 0).AddDate(2019, 01, 01).Unix(),
			UpdatedAt: time.Unix(0, 0).AddDate(2019, 01, 01).Unix(),
			Status:    pb.AccountStatus_CREATED,
			Roles:     []string{"user"},
		},
		"acct_002@domain.com": &pb.Account{
			Uid:       "acct_002@domain.com",
			Email:     "acct_002@domain.com",
			Hash:      passwords.HashAndSalt([]byte("password_002")),
			CreatedAt: time.Unix(0, 0).AddDate(2019, 01, 01).Unix(),
			UpdatedAt: time.Unix(0, 0).AddDate(2019, 01, 01).Unix(),
			Status:    pb.AccountStatus_ACTIVE,
			Roles:     []string{"user"},
		},
	}
	return r
}

func (r *Repo) Insert(ctx context.Context, params *pb.Account) (*pb.AccountID, error) {
	if params == nil {
		return nil, status.Error(codes.InvalidArgument, "empty payload")
	}
	r.data[params.Email] = params
	return &pb.AccountID{Id: params.Email, Type: pb.IDType_UID}, nil
}
func (r *Repo) Update(ctx context.Context, params *pb.PutAccountParams) (*pb.AccountID, error) {
	if params == nil {
		return nil, status.Error(codes.InvalidArgument, "empty payload")
	}
	_, ok := r.data[params.Uid]
	if !ok {
		return nil, status.Error(codes.NotFound, "not found")
	}
	r.data[params.Uid] = params.Acct
	return &pb.AccountID{Id: params.Uid, Type: pb.IDType_UID}, nil
}
func (r *Repo) Get(ctx context.Context, params *pb.AccountID) (*pb.Account, error) {
	if params == nil {
		return nil, status.Error(codes.InvalidArgument, "empty payload")
	}
	if params.Type != pb.IDType_UID {
		return nil, status.Error(codes.InvalidArgument, "can only get by Uid")
	}
	acc, ok := r.data[params.Id]
	if !ok {
		return nil, status.Error(codes.NotFound, fmt.Sprintf("account '%s' not found", params.Id))
	}
	return acc, nil
}
func (r *Repo) GetMulti(ctx context.Context, params *pb.AccountIDs) (*pb.MultiAccounts, error) {
	if params == nil {
		return nil, status.Error(codes.InvalidArgument, "empty payload")
	}
	if params.Type != pb.IDType_UID {
		return nil, status.Error(codes.InvalidArgument, "can only get by Uid")
	}
	res := &pb.MultiAccounts{}
	aId := &pb.AccountID{Type: params.Type}
	for _, id := range params.Ids {
		aId.Id = id
		a, err := r.Get(ctx, aId)
		if err != nil {
			return nil, err
		}
		res.Accounts = append(res.Accounts, a)
	}
	return res, nil
}
func (r *Repo) Delete(ctx context.Context, params *pb.AccountID) (*pb.AccountID, error) {
	if params == nil {
		return nil, status.Error(codes.InvalidArgument, "empty payload")
	}
	delete(r.data, params.Id)
	return &pb.AccountID{Id: params.Id, Type: pb.IDType_UID}, nil
}
func (r *Repo) DeleteMulti(ctx context.Context, params *pb.AccountIDs) (*pb.AccountIDs, error) {
	if params == nil {
		return nil, status.Error(codes.InvalidArgument, "empty payload")
	}
	if params.Type != pb.IDType_UID {
		return nil, status.Error(codes.InvalidArgument, "can only get by Uid")
	}
	res := &pb.AccountIDs{Type: pb.IDType_UID}
	for _, id := range params.Ids {
		delete(r.data, id)
		res.Ids = append(res.Ids, id)
	}
	return res, nil
}
