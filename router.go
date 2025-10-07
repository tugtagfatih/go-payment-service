package main

import "github.com/gin-gonic/gin"

func SetupRouter() *gin.Engine {
	router := gin.Default()
	router.GET("/ping", PingHandler)

	// Kullanıcı işlemleri için bir grup oluşturalım.
	userRoutes := router.Group("/users")
	{
		// POST http://localhost:8080/users
		userRoutes.POST("", RegisterUserHandler)
		// GET http://localhost:8080/users/:id
		userRoutes.GET("", ListUsersHandler)

	}

	return router
}
