package context

import (
	"context"

	pb "github.com/klahssen/authn/proto-gen/authz/apiv1"
)

//GetIdentityFromCtx extract Identity from jwt token in ctx
func GetIdentityFromCtx(ctx context.Context) *pb.Identity {
	jwt, _ := ctx.Value("jwt").(string)
	return &pb.Identity{
		Type:  "jwt",
		Token: jwt,
	}
}
