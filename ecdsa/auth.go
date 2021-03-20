package auth

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

const (
	expiryDays = 1
)

var (
	secretKey interface{}
	publicKey interface{}
)

func init() {
	skey, err := ioutil.ReadFile("./secret.key")
	if err != nil {
		panic(err)
	}
	caCert, err := ioutil.ReadFile("./ca.crt")
	if err != nil {
		panic(err)
	}
	pCert, err := ioutil.ReadFile("./public.crt")
	if err != nil {
		panic(err)
	}

	err = parseKeys(skey, caCert, pCert)
	if err != nil {
		panic(err)
	}
}

func parseKeys(sKey, caCert, pCert []byte) error {
	var err error
	privateKeyBlock, _ := pem.Decode(sKey)
	if privateKeyBlock == nil {
		return errors.New("private key cannot decode")
	}
	if privateKeyBlock.Type != "EC PRIVATE KEY" {
		return errors.New("private key type is not rsa")
	}
	secretKey, err = x509.ParseECPrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return errors.New("failed to parse private key")
	}

	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(caCert); !ok {
		return errors.New("invalid root cert")
	}
	publicKeyBlock, _ := pem.Decode(pCert)
	if publicKeyBlock == nil {
		return errors.New("public key cannot decode")
	}
	if publicKeyBlock.Type != "CERTIFICATE" {
		return errors.New("public key type is invalid")
	}

	cert, err := x509.ParseCertificate(publicKeyBlock.Bytes)
	if err != nil {
		return errors.New("failed to parse public key")
	}
	opt := x509.VerifyOptions{
		Roots: roots,
	}
	_, err = cert.Verify(opt)
	if err != nil {
		return errors.New("failed to verify certficate")
	}
	if cert.Subject.CommonName != "fugafuga.co.jp" {
		return errors.New("invalid subject")
	}
	publicKey = cert.PublicKey

	return nil
}

func GenerateToken(userID string, now int64) (tokenString string, err error) {
	claims := jwt.StandardClaims{
		Subject:   userID,
		IssuedAt:  now,
		ExpiresAt: time.Unix(now, 0).AddDate(0, 0, expiryDays).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// sign by secret key
	tokenString, err = token.SignedString(secretKey)
	if err != nil {
		err = errors.Wrap(err, "Failed to sign token")
		return
	}

	return
}

func VerifyToken(tokenString string) (*jwt.Token, error) {
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// check signing method
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			err := errors.New("Unexpected signing method")
			return nil, err
		}
		return publicKey, nil
	})
	if err != nil {
		err = errors.Wrap(err, "Token is invalid")
		return nil, err
	}
	if !parsedToken.Valid {
		return nil, errors.New("Token is invalid")
	}

	return parsedToken, nil
}
