package handlers

import (
	"auth-login/models"
	"auth-login/services"
	"net/http"

	"github.com/gin-gonic/gin"
)

type IHandler interface {
	Login(c *gin.Context)
}

type handler struct {
	s services.IServices
}

func NewHandler(s services.IServices) IHandler {
	return &handler{s: s}
}

func (h *handler) Login(c *gin.Context) {
     var login models.Login
	 if err := c.ShouldBindJSON(&login); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
     err := h.s.Login(login)
	 if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
        return
    }
	
	c.JSON(http.StatusOK, gin.H{"message": "login successful!"})
}
