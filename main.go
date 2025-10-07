package main

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var dbPool *pgxpool.Pool

type User struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	CreatedAt    time.Time `json:"created_at"`
	PasswordHash string    `json:"-"`
}

func main() {
	Printlinkforfirebase()
	ConnectPosgres()

	router := gin.Default()

	userRoutes := router.Group("/users")
	{
		userRoutes.POST("", RegisterUserHandler)
		userRoutes.GET("", ListUsersHandler)
	}

	log.Println("Sunucu 8080 portunda başlatılıyor...")
	router.Run(":8080")

	defer dbPool.Close()
}
