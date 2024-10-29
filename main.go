package main

import (
	"auth-login/handlers"
	"auth-login/middlewares"
	"auth-login/pkg/database"
	"auth-login/repositories"
	"auth-login/services"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// เชื่อมต่อกับฐานข้อมูล PostgreSQL
	db := database.Postgresql()
	defer db.Close()

	// สร้าง repository, service และ handler
	r := repositories.NewRepositorie(db)
	s := services.NewService(r)
	h := handlers.NewHandler(s)

	// สร้าง Gin router
	router := gin.Default()

	// กำหนดค่า CORS
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"*"}
	config.AllowMethods = []string{"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "X-Auth-Token", "Authorization"}
	config.AllowCredentials = true
	router.Use(cors.New(config))

	// กำหนดเส้นทางสำหรับการเข้าสู่ระบบ
	router.POST("/auth/login", h.Login)
	router.GET("/auth/refresh", h.RefreshToken)

	// เส้นทางที่ต้องมีการตรวจสอบสิทธิ์
	protected := router.Group("/api")
	protected.Use(middlewares.AuthMiddleware())
	{
		protected.GET("/resource", h.GetResource)
	}

	// เริ่มต้นเซิร์ฟเวอร์ที่พอร์ต 8888
	if err := router.Run(":8888"); err != nil {
		panic("Failed to run server: " + err.Error())
	}
}
