package main

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"github.com/tacheshun/envoy_ext_authz/internal/service"
	"log"
	"net"

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
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate key %v", err)
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
