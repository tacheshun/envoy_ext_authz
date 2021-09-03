package service_test

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go/v4"
	"github.com/tacheshun/envoy_ext_authz/internal/service"
	"testing"
	"time"
)

const (
	success = "\u2713"
	failed  = "\u2717"
)

func TestAuth(t *testing.T) {
	t.Log("Given the need to be able to validate json web tokens ")
	{
		testID := 0
		t.Logf("\tTest %d:\tWhen handling a single token.", testID)
		{
			const keyID = "54bb2165-71e1-41a6-af3e-7da4a0e1e2c1"
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("\t%s\tTest %d:\tShould be able to create a private key: %v", failed, testID, err)
			}
			t.Logf("\t%s\tTest %d:\tShould be able to create a private key.", success, testID)

			a, err := service.NewAuth("RS256", &service.KeyStore{Pk: privateKey})
			if err != nil {
				t.Fatalf("\t%s\tTest %d:\tShould be able to create an authenticator: %v", failed, testID, err)
			}
			t.Logf("\t%s\tTest %d:\tShould be able to create an authenticator.", success, testID)

			claims := service.Claims{
				StandardClaims: jwt.StandardClaims{
					Issuer:    "go microservice",
					Subject:   "marius.costache.b@gmail.com",
					ExpiresAt: jwt.At(time.Now().Add(8760 * time.Hour)),
					IssuedAt:  jwt.Now(),
				},
			}

			token, err := a.GenerateToken(keyID, claims)
			if err != nil {
				t.Fatalf("\t%s\tTest %d:\tShould be able to generate a JWT: %v", failed, testID, err)
			}
			t.Logf("\t%s\tTest %d:\tShould be able to generate a JWT.", success, testID)

			parsedClaims, err := a.ValidateToken(token)
			if err != nil {
				t.Fatalf("\t%s\tTest %d:\tShould be able to parse the claims: %v", failed, testID, err)
			}
			t.Logf("\t%s\tTest %d:\tShould be able to parse the claims.", success, testID)
			if exp, got := len(claims.Subject), len(parsedClaims.Subject); exp != got {
				t.Logf("\t\tTest %d:\texp: %d", testID, exp)
				t.Logf("\t\tTest %d:\tgot: %d", testID, got)
				t.Fatalf("\t%s\tTest %d:\tShould have the expected subject: %v", failed, testID, err)
			}
		}
	}
}
