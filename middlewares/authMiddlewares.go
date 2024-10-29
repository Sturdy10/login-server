package middlewares

import (
	"auth-login/auth"
	"net/http"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware เป็น middleware สำหรับตรวจสอบโทเคน
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// อ่านโทเคนจากคุกกี้
		tokenString, err := c.Cookie("access_token")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "accesstoken is not a valid token"})
			c.Abort()
			return
		}

		// ตรวจสอบโทเคน
		var claims auth.AccessClaims
		_, err = auth.ValidateToken(tokenString, &claims, auth.AccessKey)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid access token"})
			c.Abort()
			return
		}

		
		c.Set("claims", claims)
		c.Next()
	}
}


func RefreshAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// อ่าน refresh token จากคุกกี้
		refreshToken, err := c.Cookie("refresh_token")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "refreshtoken token is not valid token"})
			c.Abort()
			return
		}

		// ตรวจสอบความถูกต้องของ refresh token
		var claims auth.RefreshClaims
		_, err = auth.ValidateToken(refreshToken, &claims, auth.RefreshKey)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
			c.Abort()
			return
		}

		c.Set("claims", claims)
		c.Next()
	}
}
