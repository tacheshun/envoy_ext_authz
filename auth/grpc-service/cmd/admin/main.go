package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/dgrijalva/jwt-go/v4"
	"github.com/pkg/errors"
	"github.com/tacheshun/envoy_ext_authz/internal/service"
	"io"
	"log"
	"os"
	"time"
)

var ErrHelp = errors.New("Help")

func main() {
	logger := log.New(os.Stdout, "ADMIN : ", log.LstdFlags|log.Lmicroseconds|log.Lshortfile)

	if err := run(); err != nil {
		if errors.Cause(err) != ErrHelp {
			logger.Printf("error: %s", err)
		}
		os.Exit(1)
	}
}

func run() error {
	flag.Parse()

	switch flag.Arg(0) {
	case "genkey":
		if err := GenKey(); err != nil {
			return errors.Wrap(err, "key generation")
		}

	case "gentoken":
		kid := flag.Arg(1)
		privateKeyFile := "private.pem"
		algorithm := "RS256"
		if err := GenToken(privateKeyFile, kid, algorithm); err != nil {
			return errors.Wrap(err, "key generation")
		}

	default:
		fmt.Println("genkey: generate a set of private/public key files")
		fmt.Println("gentoken: generate a JWT for a user with claims. You also need to specify an unique kid after gentoken command")
		fmt.Println("provide a command to get more help.")

		return ErrHelp
	}

	return nil
}

// GenToken generates a JWT for the specified user.
func GenToken(privateKeyFile string, kid string, algorithm string) error {
	pkf, err := os.Open(privateKeyFile)
	if err != nil {
		return errors.Wrap(err, "opening PEM private key file")
	}
	defer pkf.Close()
	privatePEM, err := io.ReadAll(io.LimitReader(pkf, 1024*1024))
	if err != nil {
		return errors.Wrap(err, "reading PEM private key file")
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privatePEM)
	if err != nil {
		return errors.Wrap(err, "parsing PEM into private key")
	}

	a, err := service.NewAuth(algorithm, &service.KeyStore{Pk: privateKey})
	if err != nil {
		return errors.Wrap(err, "constructing auth")
	}

	claims := service.Claims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    "go microservice",
			Subject:   "marius.costache.b@gmail.com",
			ExpiresAt: jwt.At(time.Now().Add(8760 * time.Hour)),
			IssuedAt:  jwt.Now(),
		},
	}

	token, err := a.GenerateToken(kid, claims)
	if err != nil {
		return errors.Wrap(err, "generating token")
	}

	fmt.Printf("-----BEGIN TOKEN-----\n%s\n-----END TOKEN-----\n", token)

	return nil
}

// GenKey creates an x509 private/public key for service tokens.
func GenKey() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return ErrHelp
	}

	privateFile, err := os.Create("private.pem")
	if err != nil {
		return errors.Wrap(err, "creating private file")
	}
	defer privateFile.Close()

	privateBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	if err := pem.Encode(privateFile, &privateBlock); err != nil {
		return errors.Wrap(err, "encoding to private file")
	}

	asn1Bytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return errors.Wrap(err, "marshaling public key")
	}

	publicFile, err := os.Create("public.pem")
	if err != nil {
		return errors.Wrap(err, "creating public file")
	}
	defer publicFile.Close()

	publicBlock := pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	if err := pem.Encode(publicFile, &publicBlock); err != nil {
		return errors.Wrap(err, "encoding to public file")
	}

	fmt.Println("private and public key files generated")
	return nil
}
