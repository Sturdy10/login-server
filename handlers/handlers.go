package handlers

import (
	"auth-login/auth"
	"auth-login/models"
	"auth-login/services"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type IHandler interface {
	Login(c *gin.Context)
	RefreshToken(c *gin.Context)
	GetResource(c *gin.Context)
}

type handler struct {
	s services.IServices
}

func NewHandler(s services.IServices) IHandler {
	return &handler{s: s}
}

func (h *handler) Login(c *gin.Context) {
	var req models.Login
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ip := auth.GetClientIP(c.Request)
	os := auth.GetOS()

	_, err := h.s.Login(req, ip, os, c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "login successful!"})
}


func (h *handler) RefreshToken(c *gin.Context) {
	// ดึง refresh token จากคุกกี้
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token required"})
		return
	}

	refreshClaims := &auth.RefreshClaims{}
	if _, err := auth.ValidateToken(refreshToken, refreshClaims, auth.RefreshKey); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}


	ip := auth.GetClientIP(c.Request)
	os := auth.GetOS()


	accessClaims := auth.NewAccessClaims(refreshClaims.UID, ip, os)
	newAccessToken, err := auth.GenerateToken(accessClaims, auth.AccessKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}


	newRefreshClaims := auth.NewRefreshClaims(refreshClaims.UID)
	newRefreshToken, err := auth.GenerateToken(newRefreshClaims, auth.RefreshKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}


	auth.SetCookie(c, "access_token", newAccessToken, auth.AccessTokenExp)
	auth.SetCookie(c, "refresh_token", newRefreshToken, auth.RefreshTokenExp)

	fmt.Println("newAccessToken: ", newAccessToken)


	c.JSON(http.StatusOK, gin.H{"message": "Token refreshed successfully"})
}

func (h *handler) GetResource(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Welcome resource successful!"})
}