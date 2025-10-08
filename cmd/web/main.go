package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/tugtagfatih/go-payment-service/internal/auth"
	"github.com/tugtagfatih/go-payment-service/internal/config"
	"github.com/tugtagfatih/go-payment-service/internal/database"
	"github.com/tugtagfatih/go-payment-service/internal/handlers"
)

func main() {
	// 1. Konfigürasyonu Yükle
	// main.go `cmd/web` içinde olduğu için, kök dizindeki .env dosyasına ulaşmak
	// için iki seviye yukarı çıkıyoruz ('../../').
	cfg, err := config.LoadConfig("/home/user/postgres.env")
	if err != nil {
		log.Fatalf("Konfigürasyon yüklenemedi: %v", err)
	}

	// --- GEÇİCİ HATA AYIKLAMA KODU ---
	log.Printf("Yüklenen Host: [%s]", cfg.DBHost)
	log.Printf("Yüklenen Kullanıcı: [%s]", cfg.DBUser)
	log.Printf("Yüklenen Veritabanı: [%s]", cfg.DBName)
	// --- HATA AYIKLAMA KODU SONU ---

	// 2. Veritabanına Bağlan
	dbPool, err := database.Connect(cfg.DSN)
	if err != nil {
		log.Fatalf("Veritabanı hatası: %v", err)
	}
	defer dbPool.Close()

	// 3. Auth Servisini Başlat
	authService, err := auth.NewAuth(cfg.JWTSecretKey)
	if err != nil {
		log.Fatalf("Auth servisi başlatılamadı: %v", err)
	}

	// 4. Handler'ları, bağımlılıkları (db, auth) ile birlikte başlat (Dependency Injection)
	h := handlers.NewHandler(dbPool, authService)

	// 5. Router'ı Kur ve Rotaları Tanımla
	router := gin.Default()

	// Public Rotalar (kimlik doğrulaması gerektirmez)
	publicRoutes := router.Group("/")
	{
		authGroup := publicRoutes.Group("/auth")
		{
			authGroup.POST("/register", h.RegisterUserHandler)
			authGroup.POST("/login", h.LoginHandler)
		}
		publicRoutes.GET("/listings", h.ListListingsHandler)
	}

	// Korumalı (Protected) Rotalar (geçerli bir JWT gerektirir)
	api := router.Group("/api")
	api.Use(authService.Middleware()) // Auth middleware'ini bu gruba uygula
	{
		api.GET("/profile", h.ProfileHandler)

		walletGroup := api.Group("/wallet")
		{
			walletGroup.GET("", h.GetWalletHandler)
			walletGroup.POST("/deposit", h.DepositHandler)
			walletGroup.GET("/history", h.GetTransactionHistoryHandler)
		}

		listingsGroup := api.Group("/listings")
		{
			listingsGroup.POST("", h.CreateListingHandler)
			listingsGroup.POST("/:id/buy", h.BuyListingHandler)
		}
	}

	// 6. Sunucuyu Başlat
	log.Println("Sunucu 8080 portunda başlatılıyor...")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Sunucu başlatılamadı: %v", err)
	}
}
