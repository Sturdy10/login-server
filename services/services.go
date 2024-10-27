package services

import (
	"auth-login/models"
	"auth-login/repositories"
	"fmt"
	"log"
	"regexp"
)

type IServices interface {
	Login(login models.Login) error
}

type service struct {
	r repositories.IRepository
}

func NewService(r repositories.IRepository) IServices {
	return &service{r: r}
}

func (s *service) Login(login models.Login) error {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(login.OrgpplEmail) {
		return fmt.Errorf("invalid email format")
	}

	err := s.r.Login(login)
	if err != nil {
		log.Println(err.Error())
		return err
	}
	return nil
}
