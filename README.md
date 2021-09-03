# Envoy Ext_Authz
- Envoy External Authorization Filter for validating JSON Web Tokens

## Requirements
- you will need Docker installed

## Setup

- run `docker-compose up -d --build`
- generate a jwt using the public and private keys provided in the repository.
- using the admin tool inside auth/grpc-service: 
  `go run ./cmd/admin gentoken`
    
- if you want to recreate public/private keypair, manually delete the keys from auth/grpc-service
and run `go run ./cmd/admin genkey` . After that, you may want to generate another jwt as well.

## Test
- from auth/grpc-service run: `go test ./...`