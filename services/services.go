package services

import (
	"auth-login/auth"
	"auth-login/models"
	"auth-login/pkg/utils"
	"auth-login/repositories"

	"github.com/gin-gonic/gin"
)

type IServices interface {
	Login(req models.Login, ip, os string, c *gin.Context) (models.LoginResponse, error) 
}

type service struct {
	r repositories.IRepository
}

func NewService(r repositories.IRepository) IServices {
	return &service{r: r}
}

func (s *service) Login(req models.Login, ip, os string, c *gin.Context) (models.LoginResponse, error) {
	if err := utils.ValidateEmail(req.OrgpplEmail); err != nil {
		return models.LoginResponse{}, err
	}

	response, err := s.r.Login(req)
	if err != nil {
		return models.LoginResponse{}, err
	}

	accessClaims := auth.NewAccessClaims(response.OrgpplID, ip, os)
	refreshClaims := auth.NewRefreshClaims(response.OrgpplID)

	accessToken, err := auth.GenerateToken(accessClaims, auth.AccessKey) // ส่ง key สำหรับ access token
	if err != nil {
		return models.LoginResponse{}, err
	}

	refreshToken, err := auth.GenerateToken(refreshClaims, auth.RefreshKey) // ส่ง key สำหรับ refresh token
	if err != nil {
		return models.LoginResponse{}, err
	}

	// ใช้ c *gin.Context ในการตั้งค่า cookie
	auth.SetCookie(c, "access_token", accessToken, auth.AccessTokenExp)
	auth.SetCookie(c, "refresh_token", refreshToken, auth.RefreshTokenExp)

	return response, nil
}
