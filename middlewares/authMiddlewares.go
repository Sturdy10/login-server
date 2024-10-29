package middlewares

import (
	"net/http"

	"auth-login/auth"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware ตรวจสอบ JWT token สำหรับการเข้าถึงทรัพยากรที่ต้องการการตรวจสอบสิทธิ์
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the access token from the cookie
		tokenString, err := c.Cookie("access_token")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Access token is missing"})
			c.Abort()
			return
		}

		// Validate the access token
		claims, err := auth.ValidateAccessToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid access token"})
			c.Abort()
			return
		}

		// Store claims in the context for use in the request handlers
		c.Set("claims", claims)

		// Continue to the next middleware/handler
		c.Next()
	}
}

func RefreshMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// รับ refresh token จากคุกกี้
		refreshToken, err := c.Cookie("refresh_token")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token is missing"})
			c.Abort()
			return
		}

		// ตรวจสอบความถูกต้องของ refresh token
		claims, err := auth.ValidateRefreshToken(refreshToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
			c.Abort()
			return
		}

		// เก็บ claims ใน context เพื่อใช้ใน request handlers
		c.Set("refresh_claims", claims)

		// ดำเนินการต่อไปยัง middleware/handler ถัดไป
		c.Next()
	}
}
