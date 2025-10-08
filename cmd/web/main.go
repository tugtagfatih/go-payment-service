package main

import (
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	payment/models
)

var jwtSecretKey []byte
var dbPool *pgxpool.Pool

func main() {
	Printlinkforfirebase()
	ConnectPosgres()
	jwtSecretKey = []byte(os.Getenv("JWT_SECRET_KEY"))
	if string(jwtSecretKey) == "" {
		log.Fatal("JWT_SECRET_KEY environment variable not set")
	}
	router := gin.Default()

	authRoutes := (router.Group("/auth"))
	{
		authRoutes.POST("/login", LoginHandler)
		authRoutes.POST("/register", RegisterUserHandler)
	}
	router.GET("/listings", ListListingsHandler)
	apiRoutes := router.Group("/api").Use(AuthMiddleware())
	{
		apiRoutes.GET("/profile", ProfileHandler)
		apiRoutes.POST("/listings", CreateListingHandler)
		apiRoutes.GET("/users", ListUsersHandler)
		apiRoutes.GET("/wallet", GetWalletHandler)
		apiRoutes.POST("/wallet/deposit", DepositHandler)
		apiRoutes.POST("/listings/:id/buy", BuyListingHandler)
		apiRoutes.GET("/wallet/history", GetTransactionHistoryHandler)
	}
	log.Println("Sunucu 8080 portunda başlatılıyor...")
	router.Run(":8080")

	defer dbPool.Close()
}

