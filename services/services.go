package services

import (
	"auth-login/auth"
	"auth-login/models"
	"auth-login/repositories"
	"fmt"
	"regexp"

	"github.com/gin-gonic/gin"
)

type IServices interface {
	Login(c *gin.Context, login models.Login) (models.LoginResponse, error)
}

type service struct {
	r repositories.IRepository
}

func NewService(r repositories.IRepository) IServices {
	return &service{r: r}
}
func validateEmail(email string) error {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// Implementing the IServices interface
func (s *service) Login(c *gin.Context, login models.Login) (models.LoginResponse, error) {
	if err := validateEmail(login.OrgpplEmail); err != nil {
		return models.LoginResponse{}, err
	}

	loginResponse, err := s.r.Login(login)
	if err != nil {
		return models.LoginResponse{}, err
	}

	// Get the user's IP address and operating system
	ip := auth.GetClientIP(c.Request)
	os := auth.GetOS()

	// Create claims for access and refresh tokens
	accessClaims := auth.CreateAccessClaims(loginResponse.OrgpplID, ip, os)
	refreshClaims := auth.CreateRefreshClaims(loginResponse.OrgpplID)

	// Generate access and refresh tokens
	accessToken, err := auth.CreateAccessToken(accessClaims)
	if err != nil {
		return models.LoginResponse{}, err
	}

	refreshToken, err := auth.CreateRefreshToken(refreshClaims)
	if err != nil {
		return models.LoginResponse{}, err
	}

	// Set cookies for the tokens
	auth.SetAccessTokenCookie(c, accessToken)
	auth.SetRefreshTokenCookie(c, refreshToken)

	return models.LoginResponse{OrgpplID: loginResponse.OrgpplID}, nil
}
