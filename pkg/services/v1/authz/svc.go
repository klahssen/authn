package authz

import (
	"context"

	pb "github.com/klahssen/authn/proto-gen/authz/apiv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service struct{}

func New() *Service { return &Service{} }

func (s *Service) Check(ctx context.Context, params *pb.Req) (*pb.Resp, error) {
	if params == nil {
		return nil, status.Error(codes.InvalidArgument, "empty payload")
	}
	switch params.Action {
	//case actions.AccountsUpdateEmail
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
