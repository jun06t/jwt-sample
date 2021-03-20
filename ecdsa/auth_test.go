package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	. "github.com/smartystreets/goconvey/convey"
)

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type Claim struct {
	Sub string `json:"sub"`
	Typ string `json:"typ"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

func TestGenerateToken(t *testing.T) {
	t.Parallel()

	Convey("Given userID", t, func() {
		id := "user001"

		Convey("When generating token", func() {
			token, err := GenerateToken(id, 1400000000)

			Convey("Then it generates new token", func() {
				So(err, ShouldBeNil)

				encoded := strings.Split(token, ".")
				So(len(encoded), ShouldEqual, 3)

				headerBuf, _ := base64.StdEncoding.DecodeString(encoded[0])
				header := Header{}
				json.Unmarshal(headerBuf, &header)
				So(header.Alg, ShouldEqual, "ES256")
				So(header.Typ, ShouldEqual, "JWT")

				claimBuf, _ := base64.StdEncoding.DecodeString(encoded[1])
				claim := Claim{}
				json.Unmarshal(claimBuf, &claim)
				So(claim.Sub, ShouldEqual, "user001")
				So(claim.Iat, ShouldEqual, 1400000000)
			})
		})
	})
}

func TestVerifyToken(t *testing.T) {
	t.Parallel()

	Convey("Given token", t, func() {
		now := time.Now().Unix() - 1000
		tokenString, _ := GenerateToken("user001", now)

		Convey("When alg is changed to none", func() {
			dummyToken := make([]string, 3)
			header := Header{
				Alg: "none",
				Typ: "JWT",
			}
			headerBuf, _ := json.Marshal(header)
			dummyToken[0] = base64.StdEncoding.EncodeToString(headerBuf)
			claim := Claim{
				Sub: "malicious",
				Typ: "JWT",
				Iat: now,
				Exp: 2000000000,
			}
			claimBuf, _ := json.Marshal(claim)
			dummyToken[1] = base64.StdEncoding.EncodeToString(claimBuf)
			dummyToken[2] = ""

			_, err := VerifyToken(strings.Join(dummyToken, "."))

			Convey("Then it returns error", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "Token is invalid: Unexpected signing method")
			})
		})

		Convey("When token has expired", func() {
			now = now - 3*24*60*60
			tokenString, _ = GenerateToken("user001", now)
			_, err := VerifyToken(tokenString)

			Convey("Then it returns error", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "Token is invalid: Token is expired")
			})
		})

		Convey("When token is valid", func() {
			parsedToken, err := VerifyToken(tokenString)

			Convey("Then it returns no error", func() {
				So(err, ShouldBeNil)
				claims, _ := parsedToken.Claims.(jwt.MapClaims)
				So(claims["sub"], ShouldEqual, "user001")
			})
		})
	})
}
