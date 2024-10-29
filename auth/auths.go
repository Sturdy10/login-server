package auth

import (
	"auth-login/models"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var (
	AccessTokenExp  = 10 * time.Second
	RefreshTokenExp = 30 * time.Second
	accessKey       = []byte("secret_access")
	refreshKey      = []byte("secret_refresh")
)

func CreateAccessClaims(uid string, ip string, os string) models.AccessClaims {
	return models.AccessClaims{
		UID: uid,
		IP:  ip,
		OS:  os,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenExp)),
		},
	}
}

func CreateAccessToken(claims models.AccessClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(accessKey)
}

func CreateRefreshClaims(uid string) models.RefreshClaims {
	return models.RefreshClaims{
		UID: uid,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(RefreshTokenExp)),
		},
	}
}

func CreateRefreshToken(claims models.RefreshClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(refreshKey)
}

func SetAccessTokenCookie(c *gin.Context, token string) {
	c.SetCookie("access_token", token, int(AccessTokenExp.Seconds()), "/", "", true, true)
}

func SetRefreshTokenCookie(c *gin.Context, token string) {
	c.SetCookie("refresh_token", token, int(RefreshTokenExp.Seconds()), "/", "", true, true)
}

func ValidateAccessToken(tokenString string) (*models.AccessClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.AccessClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return accessKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*models.AccessClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func ValidateRefreshToken(tokenString string) (*models.RefreshClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return refreshKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*models.RefreshClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
