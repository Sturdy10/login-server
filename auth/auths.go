package auth

import (
	"fmt"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

func LoadEnv() error {
	return godotenv.Load()
}

const (
	AccessTokenExp  = 10 * time.Second
	RefreshTokenExp = 30 * time.Second
)

var (
	AccessKey  = os.Getenv("ACCESS_KEY")
	RefreshKey = os.Getenv("REFRESH_KEY")
)

type Claims interface {
	jwt.Claims
}

// AccessClaims and RefreshClaims โครงสร้าง claims สำหรับ access และ refresh
type AccessClaims struct {
	UID string `json:"uid"`
	IP  string `json:"ip"`
	OS  string `json:"os"`
	jwt.RegisteredClaims
}

type RefreshClaims struct {
	UID string `json:"uid"`
	jwt.RegisteredClaims
}

// NewAccessClaims สร้าง AccessClaims พร้อมกำหนด exp
func NewAccessClaims(uid, ip, os string) AccessClaims {
	return AccessClaims{
		UID: uid,
		IP:  ip,
		OS:  os,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenExp)),
		},
	}
}

// NewRefreshClaims สร้าง RefreshClaims พร้อมกำหนด exp
func NewRefreshClaims(uid string) RefreshClaims {
	return RefreshClaims{
		UID: uid,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(RefreshTokenExp)),
		},
	}
}


func GenerateToken(claims Claims, key string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(key))
}


func SetCookie(c *gin.Context, name, token string, exp time.Duration) {
	c.SetCookie(name, token, int(exp.Seconds()), "/", "", true, true)
}


func ValidateToken(tokenString string, claims Claims, key string) (Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(key), nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return token.Claims, nil
}
