package models

import "github.com/golang-jwt/jwt/v5"

type Login struct {
	OrgpplEmail   string `json:"email" binding:"required"`
	PplcrPassword string `json:"password"`
}

type LoginResponse struct {
	OrgpplID string `json:"uid"`
}

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
