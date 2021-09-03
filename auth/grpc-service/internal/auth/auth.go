package auth

import (
	"context"
	envoy_api_v3_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/tacheshun/envoy_ext_authz/internal/service"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/genproto/googleapis/rpc/status"
	"strings"
)

type AuthorizationServer struct {
	auth service.Auth
}

var _ envoy_service_auth_v3.AuthorizationServer = &AuthorizationServer{}

// New creates a new authorization AuthorizationServer.
func New(auth *service.Auth) envoy_service_auth_v3.AuthorizationServer {
	return &AuthorizationServer{*auth}
}

// Check implements authorization's Check interface which performs authorization check based on the
// attributes associated with the incoming request.
func (s *AuthorizationServer) Check(
	ctx context.Context,
	req *envoy_service_auth_v3.CheckRequest) (*envoy_service_auth_v3.CheckResponse, error) {
	authorization := req.Attributes.Request.Http.Headers["authorization"]
	extracted := strings.Fields(authorization)
	if len(extracted) == 2 && extracted[0] == "Bearer" {
		valid, user := s.auth.Check(extracted[1])
		if valid {
			return &envoy_service_auth_v3.CheckResponse{
				HttpResponse: &envoy_service_auth_v3.CheckResponse_OkResponse{
					OkResponse: &envoy_service_auth_v3.OkHttpResponse{
						Headers: []*envoy_api_v3_core.HeaderValueOption{
							{
								Append: &wrappers.BoolValue{Value: false},
								Header: &envoy_api_v3_core.HeaderValue{
									// For a successful request, the authorization AuthorizationServer sets the
									// x-current-user value.
									Key:   "x-current-user",
									Value: user,
								},
							},
						},
					},
				},
				Status: &status.Status{
					Code: int32(code.Code_OK),
				},
			}, nil
		}
	}

	return &envoy_service_auth_v3.CheckResponse{
		Status: &status.Status{
			Code: int32(code.Code_PERMISSION_DENIED),
			Message: "Permission Denied",
		},
	}, nil
}