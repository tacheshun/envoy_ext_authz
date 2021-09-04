# Envoy Ext_Authz
- Envoy External Authorization Filter for validating JSON Web Tokens

## Requirements
- you will need Docker installed
- (optional) golang installed on local machine if you want to use go admin tool for keypair and/or token generation

## Setup and run

- run `docker-compose up --build -d`
- generate a jwt using the public and private keys provided in the repository by using the admin tool inside auth/grpc-service: 
  `go run ./cmd/admin gentoken <uuid-kid>`, where uuid-kid is an unique key ID header parameter. Alternatively, you can grab an already generated token from config/token directory. Test token was generated using the keypair provided in _auth/grpc-service_ folder.
- grab a token and issue a GET request with it: `curl -v -H "Authorization: Bearer <token>" localhost:8000/service`
- if you want to recreate public/private keypair, manually delete the keys from _auth/grpc-service_
and run `go run ./cmd/admin genkey` . After that, you may want to generate another jwt as well.
-  when you are done, don't forget to clean up `docker-compose down --remove-orphans`

## Test
- from auth/grpc-service run: `go test ./...`
