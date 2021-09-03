package main

import (
	"flag"
	"fmt"
	"github.com/dgrijalva/jwt-go/v4"
	"github.com/tacheshun/envoy_ext_authz/internal/service"
	"io"
	"log"
	"net"
	"os"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	authv3 "github.com/tacheshun/envoy_ext_authz/internal/auth"
	"google.golang.org/grpc"
)

func main() {
	port := flag.Int("port", 9002, "gRPC port")

	flag.Parse()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen to %d: %v", *port, err)
	}
	privateKeyFile := "private.pem"
	pkf, err := os.Open(privateKeyFile)
	if err != nil {
		log.Fatalf( "opening PEM private key file")
	}
	defer pkf.Close()
	privatePEM, err := io.ReadAll(io.LimitReader(pkf, 1024*1024))
	if err != nil {
		log.Fatalf( "reading PEM private key file")
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privatePEM)
	if err != nil {
		log.Fatalf( "parsing PEM into private key")
	}

	grpcServer := grpc.NewServer()
	serviceAuth, err := service.NewAuth("RS256",  &service.KeyStore{Pk: privateKey})
	if err != nil {
		log.Fatalf("failed to start the serviceAuth %v", err)
	}
	server := authv3.New(serviceAuth)

	envoy_service_auth_v3.RegisterAuthorizationServer(grpcServer, server)

	log.Printf("starting gRPC server on: %d\n", *port)

	if err := grpcServer.Serve(lis);err != nil {
		log.Fatalf("failed to start gRPC server %v", err)
	}
}
