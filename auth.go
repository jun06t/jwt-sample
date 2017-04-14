package auth

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

const (
	expiryDays = 1
)

var (
	rawPublicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAw8eiDb307pWnvR2XL0CW
OD/Nscc5ZTN7peZzuyjOQSzqEYjEa4XxUjI9KgdJD6zYW5h5BSA0Xa2quagJtZCS
j5BjZ5YCF9rMaLAeUAmifKJyGj0Z9yeN7Hil2dOtu71Kf3+fU28sRGq+OQrwdPCd
12zu+gz29UIwGlfV7rXzZFuKWB479WUCuWTsgWRd0XV8dGNTGvpqXn7HXzmt+3RJ
vIMwAvtKePFBWR4f/sIwSCn1W8ej/78+kVmHc1OS9Cnf1g9JFjZpoT4muJIWUxpD
WH5UuMAY89aVXi91EFyD1yQQYMYrhXlEALFOAUvqSlNsbGm9oERLnvW5r4Rcvjqj
O2G6yHYFczPWtb2ssmrjfERCkNNkiBVrHAgKdc/tuCCL0BLzSQirGdligv3lvUgF
RihrdYbFxV7BSYZbCXFQ6ZtEyfDpYKUDTl56uKTzLu9OgGAwfv887Pqdlu9lZfmB
T/sgwD02zepiy04XKLkF/J82stfsabhfT5eDHFSrjkchhLSQnv+PRQRVqw8qxOGC
rgpPWTNo1Gn2r8bpI365QApVsnhRdDCAuuSQMoUdz4fOwM5CCqgvM6Gl5sZSpxGt
p4KroIo6Em6vRRuuSaoSOY67QNikpuo/H8oQ1jkpXQIqbGGYd5olNkpPJssU7Bss
Horlxxaj4cGE2OYxaJmRpL0CAwEAAQ==
-----END PUBLIC KEY-----`)

	rawSecretKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIJKgIBAAKCAgEAw8eiDb307pWnvR2XL0CWOD/Nscc5ZTN7peZzuyjOQSzqEYjE
a4XxUjI9KgdJD6zYW5h5BSA0Xa2quagJtZCSj5BjZ5YCF9rMaLAeUAmifKJyGj0Z
9yeN7Hil2dOtu71Kf3+fU28sRGq+OQrwdPCd12zu+gz29UIwGlfV7rXzZFuKWB47
9WUCuWTsgWRd0XV8dGNTGvpqXn7HXzmt+3RJvIMwAvtKePFBWR4f/sIwSCn1W8ej
/78+kVmHc1OS9Cnf1g9JFjZpoT4muJIWUxpDWH5UuMAY89aVXi91EFyD1yQQYMYr
hXlEALFOAUvqSlNsbGm9oERLnvW5r4RcvjqjO2G6yHYFczPWtb2ssmrjfERCkNNk
iBVrHAgKdc/tuCCL0BLzSQirGdligv3lvUgFRihrdYbFxV7BSYZbCXFQ6ZtEyfDp
YKUDTl56uKTzLu9OgGAwfv887Pqdlu9lZfmBT/sgwD02zepiy04XKLkF/J82stfs
abhfT5eDHFSrjkchhLSQnv+PRQRVqw8qxOGCrgpPWTNo1Gn2r8bpI365QApVsnhR
dDCAuuSQMoUdz4fOwM5CCqgvM6Gl5sZSpxGtp4KroIo6Em6vRRuuSaoSOY67QNik
puo/H8oQ1jkpXQIqbGGYd5olNkpPJssU7BssHorlxxaj4cGE2OYxaJmRpL0CAwEA
AQKCAgEAtX9ZCIxViOlMe9H22mNx3+umcW1UFDHKK16dY6DMtTdCN8cm8NdXhO/2
LARdAx8l5KRRbSMR6NabM0pI1f2VIWql/N3gSuUYIuVC9Mg5znl6dkC21Z3hwJuI
hYvrv+QYMGLL/blOvI6IkrFFgeOfMJtYYI+sUmpt1b4gIhCj9yG1+0LsKu7du6mI
Z9v37bqRCgUagiQsgDXf9rOuSzLfONgVpm33+G8QOeHnn3G++OeNAuztaKaPBoiN
Paj4z0oSrIu3IdSH0Geh1fH4qEnsrRlQyYWsnEEOcCZmzCg4QTa5yD1vE2n8VPgK
bMFIDmeQWGEe3njx8gezgLegkuohb8UuR6xjCE9av4hPIjb2cIA25oMXZGOnjprz
Ug/UPDHmNwI6BOccrsyuT+eFH7+XXYHNqNFsCxLJVJk5e45VuB3VN803zWD/cUPM
mBGpTXa2N3pOrNh0CKRxi9qCEfyaCf7eEhzW0cTjqJlVZMianzfY826LxKrUFBj5
d5xYsgCrdil/UOYcRbDyef96f50tt6BRjZZvkw6AAye2BqS1bJD87VWMuSRXkCtB
lix1UA89Xrli6nmQcGLRmdNE7ImlG0i8xPZ2x5Keypq18Oc2P7L2odPs34dDg+vR
j8F3qIeFtm8+9erc1EXv8KQgtl9rQKqC1lpnnic5tuRlwlvT5DECggEBAP21o5F+
HeHvtdwmbLDTYttO4rdsr19RE0oYsQWeAmbrS+FOrKY++l2NIxzPNFUIKoWBD1CR
x1pKWitBZvxYPy1Jck1JgwutN3DUtVEatM44Bny8RDSonL7vvtvVlN+XL+0Jw6JZ
phBuRAj6LLGLTBVt05Usnw8NWCb1vPyyzI1Gq5gaLt6jMGOhwOL8fOMbQqxAmYGe
2tWmPS9+qts9sC5QM2F2fDoHJ8eRt5XAEA9BEohG6fBc5ER0baQlUsMY7n/0rK8o
6M8QQVORnhPTa/LWCm9Djq2lu7QDQ8oCi9SYNeXab4p33srhJ25u3m0avfdTitvq
uX28DlnLWHDB2vcCggEBAMWMHBmxTCzCad1iS258Rb4RkXLTw37rwnLvRR9dh8Ei
RhnOg6vZkRfDywOrMWeobWRFjZqmrwa4q1rWq05i8ErnAlibjoyGB9At6OhGkrPo
L1tHbzqOPcJAX8UqELcHvn+evne8T//jYZ0AAMYR+X12pJwhhCYfhrJg6IevWKrZ
Lzc853fIydtfNZ79fel7cF1T8c1ohF2kj3sc0ET69U/sFlRQdyhgpR5eZFvGdicB
nPxwUPybxzOFY1ZUXV0eiVJvbr5h0ZZs88wnnD6flcycf++puN/e72xogLUiFuhf
8e7RTtMkSUcm+r5Y6uiyeGaoF3cFCHLgNbL+BtlifOsCggEBAPdmP1lp9PPUD6/c
3FJV32lh9FzPI/g7lCbGCyEiIs9/lR/g2yTF9thw/5NhTnO4odZLssZrUU1vgZv6
i9V4rCqaG1bYX2xsfcqN8T1kYHlTUqgh4hTDcw4RtTijfifGQxrPUbEn4HLXQ4rJ
gfmjjw66aP9nYreH2LUtHhwAssz04/FPXvMFiPMu0WvGsHW5qHtWBxrJ8DU0hSei
SjO+ZOXUmTXqF1tyjMzkAHSLtF1bpBm1pPwZaRKDwkK1jo3m6vNlgVrQ9qyr+jfm
oJJOsU48gDJdW21jVrVEFb+QWhB2WOCJ8AjDuUJ26j+a51TXJfVexuKKclT0o73W
N6jEsKMCggEBAKeadyDpRvrWu6EDy4Hi1/0pxKCKwFvHxQNks92nqg0XeihdCWPd
RHfIO09SiKkswhsH09t5PhhSx7dbWJ453St/kYMB/9CDys86lFe1wLP482zbT6h7
lDRiD58lUGcpn9uBIJJP6APvtBrTLNTf3TAwX/rDiO4bY1mmVMMB5xWVDLUt7Ci5
52FDByhsY86bVzsnhIjE+0DD5KQMTzunPEhhwpQobOCKFq2MYlNnL0lq2flnhZ68
wCabLivJiij+Rn31Yx0NuxeIOtRkavDKzvp5cSYydlMiPzpX85M6Z/shpA798IW9
TJqcnLKwmCVzfimCxd3KHF/ykDzbv43iPJ8CggEAH4iGYpdRDjVM5H17QBMkDxxC
Xfa29Q0QJ4I/0hSTBFUrXh64oykwohmi6OXMn7gM2AoPJo8OWCytTTQruQ4sFH1A
3aUwqhIFHzh7/vBZEY2dvVlom5XWpAlXMA8DJPxJG2HROfUMttfQjWjz6UlO4QWN
gdQFLGfAqrxQNNHrF0XOnLTE9yY2fnJewYeSpode4niNMRG0n+9/5MBpd0FGoFzd
JQmOJYAe/Z0E9RdY5iH9B5su7Fk7kCJFL/qRystSpRnUdOFgP8GdqU1ilz5wBoBX
XtrgK2rkGLqvf0is3zma6Fc0m/C2Jg/mv8vHNeYzqLw2uf8AZX8GJMNjFxkCtQ==
-----END RSA PRIVATE KEY-----`)

	secretKey interface{}
	publicKey interface{}
)

func init() {
	err := parseKeys(rawSecretKey, rawPublicKey)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func parseKeys(rawSK []byte, rawPK []byte) error {
	var err error
	privateKeyBlock, _ := pem.Decode(rawSK)
	if privateKeyBlock == nil {
		return errors.New("Private key cannot decode")
	}
	if privateKeyBlock.Type != "RSA PRIVATE KEY" {
		return errors.New("Private key type is not rsa")
	}
	secretKey, err = x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return errors.New("Failed to parse private key")
	}

	publicKeyBlock, _ := pem.Decode(rawPK)
	if publicKeyBlock == nil {
		return errors.New("Public key cannot decode")
	}
	if publicKeyBlock.Type != "PUBLIC KEY" {
		return errors.New("Public key type is invalid")
	}

	publicKey, err = x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return errors.New("Failed to parse public key")
	}

	return nil
}

func GenerateToken(userID string, now int64) (tokenString string, err error) {
	claims := jwt.StandardClaims{
		Subject:   userID,
		IssuedAt:  now,
		ExpiresAt: time.Unix(now, 0).AddDate(0, 0, expiryDays).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

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
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			err := errors.New("Unexpected signing method")
			return nil, err
		}
		return publicKey, nil
	})
	if err != nil || !parsedToken.Valid {
		err = errors.Wrap(err, "Token is invalid")
		return nil, err
	}

	return parsedToken, nil
}
