# Envoy Ext_Authz
- Envoy External Authorization Filter for validating JSON Web Tokens

## Requirements
- you will need Docker installed

## Setup and run

- run `docker-compose up --build -d`
- generate a jwt using the public and private keys provided in the repository by using the admin tool inside auth/grpc-service: 
  `go run ./cmd/admin gentoken`
- alternatively, you can grab an already generated token from config/token directory.
- grab a token and issue a GET request with it: `curl -v -H "Authorization: Bearer <token>" localhost:8000/service`
- if you want to recreate public/private keypair, manually delete the keys from auth/grpc-service
and run `go run ./cmd/admin genkey` . After that, you may want to generate another jwt as well.
-  when you are done, don't forget to clean up `docker-compose down --remove-orphans`

## Test
- from auth/grpc-service run: `go test ./...`
