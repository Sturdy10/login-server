package handlers

import (
	"auth-login/auth"
	"auth-login/models"
	"auth-login/services"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type IHandler interface {
	Login(c *gin.Context)
	RefreshToken(c *gin.Context)
	GetResource(c *gin.Context)
}

type handler struct {
	s services.IServices
}

// NewHandler สร้าง handler ใหม่
func NewHandler(s services.IServices) IHandler {
	return &handler{s: s}
}

// Login ตรวจสอบข้อมูลการเข้าสู่ระบบของผู้ใช้
func (h *handler) Login(c *gin.Context) {
	var login models.Login
	if err := c.ShouldBindJSON(&login); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := h.s.Login(c, login)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "login successful!"})
}

func (h *handler) RefreshToken(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token required"})
		return
	}

	claims, err := auth.ValidateRefreshToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	ip := auth.GetClientIP(c.Request)
	os := auth.GetOS()


	accessClaims := models.AccessClaims{
		UID: claims.UID,
		IP:  ip,
		OS:  os,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),                          
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(auth.AccessTokenExp)), 
		},
	}

	newAccessToken, err := auth.CreateAccessToken(accessClaims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create access token"})
		return
	}

	newRefreshToken, err := auth.CreateRefreshToken(*claims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create refresh token"})
		return
	}


	auth.SetAccessTokenCookie(c, newAccessToken)
	auth.SetRefreshTokenCookie(c, newRefreshToken)

	fmt.Println("newAccessToken: ", newAccessToken)

	c.JSON(http.StatusOK, gin.H{"message": "Token refreshed successfully"})
}

func (h *handler) GetResource(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Welcome resource successful!"})
}
