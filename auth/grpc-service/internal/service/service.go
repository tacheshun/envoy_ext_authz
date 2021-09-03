package service

import (
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go/v4"
	"github.com/pkg/errors"
)

type Claims struct {
	jwt.StandardClaims
}

type KeyLookup interface {
	PrivateKey(kid string) (*rsa.PrivateKey, error)
	PublicKey(kid string) (*rsa.PublicKey, error)
}


type KeyStore struct {
	Pk *rsa.PrivateKey
}

func (ks *KeyStore) PrivateKey(kid string) (*rsa.PrivateKey, error) {
	return ks.Pk, nil
}

func (ks *KeyStore) PublicKey(kid string) (*rsa.PublicKey, error) {
	return &ks.Pk.PublicKey, nil
}


type Auth struct {
	algorithm string
	keyLookup KeyLookup
	method    jwt.SigningMethod
	keyFunc   func(t *jwt.Token) (interface{}, error)
	parser    *jwt.Parser
}

func NewAuth(algorithm string, keyLookup KeyLookup) (*Auth, error) {
	method := jwt.GetSigningMethod(algorithm)
	if method == nil {
		return nil, errors.Errorf("unknown algorithm %v", algorithm)
	}

	keyFunc := func(t *jwt.Token) (interface{}, error) {
		kid, ok := t.Header["kid"]
		if !ok {
			return nil, errors.New("missing key id (kid) in token header")
		}
		kidID, ok := kid.(string)
		if !ok {
			return nil, errors.New("user token key id (kid) must be string")
		}
		return keyLookup.PublicKey(kidID)
	}

	parser := jwt.NewParser(jwt.WithValidMethods([]string{algorithm}), jwt.WithAudience("candidate"))

	au := Auth{
		algorithm: algorithm,
		keyLookup: keyLookup,
		method:    method,
		keyFunc:   keyFunc,
		parser:    parser,
	}

	return &au, nil
}

func (a *Auth) GenerateToken(kid string, claims Claims) (string, error) {
	token := jwt.NewWithClaims(a.method, claims)
	token.Header["kid"] = kid

	privateKey, err := a.keyLookup.PrivateKey(kid)
	if err != nil {
		return "", errors.New("kid lookup failed")
	}

	str, err := token.SignedString(privateKey)
	if err != nil {
		return "", errors.Wrap(err, "signing token")
	}

	return str, nil
}


func (a *Auth) ValidateToken(tokenStr string) (Claims, error) {
	var claims Claims
	token, err := a.parser.ParseWithClaims(tokenStr, &claims, a.keyFunc)
	if err != nil {
		return Claims{}, errors.Wrap(err, "parsing token")
	}

	if !token.Valid {
		return Claims{}, errors.New("invalid token")
	}

	return claims, nil
}

func (a *Auth) Check(key string) (bool, string) {
	claims, err := a.ValidateToken(key)
	if err != nil {
		return false, ""
	}
	return true, claims.Subject
}

