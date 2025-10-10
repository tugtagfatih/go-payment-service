package main

import (
	"log"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/tugtagfatih/go-payment-service/firebase"
	"github.com/tugtagfatih/go-payment-service/internal/auth"
	"github.com/tugtagfatih/go-payment-service/internal/config"
	"github.com/tugtagfatih/go-payment-service/internal/database"
	"github.com/tugtagfatih/go-payment-service/internal/handlers"
)

func main() {
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
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:5173"}
	router.Use(cors.New(config))

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
		profileGroup := api.Group("/profile")
		{
			profileGroup.GET("", h.ProfileHandler)
			profileGroup.PUT("/change-password", h.ChangePasswordHandler)
			profileGroup.PUT("/bank-info", h.UpdateUserBankInfoHandler)
		}

		walletGroup := api.Group("/wallet")
		{
			walletGroup.GET("", h.GetWalletHandler)
			walletGroup.POST("/notifications", h.CreatePaymentNotificationHandler)
			walletGroup.GET("/history", h.GetTransactionHistoryHandler)
			walletGroup.POST("/withdraw", h.CreateWithdrawalRequestHandler)
		}
		adminRoutes := router.Group("/admin")
		{
			adminRoutes.GET("/notifications", h.ListPaymentNotificationsHandler)
			adminRoutes.POST("/notifications/:id/reject", h.RejectPaymentNotificationHandler)
			adminRoutes.POST("/notifications/:id/approve", h.ApprovePaymentNotificationHandler)
			adminRoutes.GET("/withdrawals", h.ListWithdrawalRequestsHandler)
			adminRoutes.POST("/withdrawals/:id/approve", h.ApproveWithdrawalRequestHandler)
			// Sadece 'admin' veya 'master_admin' rollerinin erişebileceği endpoint
			adminRoutes.POST("/users/:id/grant-approver", authService.RoleMiddleware("admin", "master_admin"), h.GrantApproverHandler) // Yeni bir handler

			// Sadece 'master_admin'in erişebileceği endpoint
			masterAdminRoutes := router.Group("/master-admin").Use(authService.Middleware(), authService.RoleMiddleware("master_admin"))
			{
				masterAdminRoutes.POST("/users/:id/grant-admin", h.GrantAdminHandler) // Yeni bir handler
			}
		}

		listingsGroup := api.Group("/listings")
		{
			listingsGroup.POST("", h.CreateListingHandler)
			listingsGroup.POST("/:id/buy", h.BuyListingHandler)
		}
	}

	// 6. Sunucuyu Başlat
	log.Println("Sunucu 8080 portunda başlatılıyor...")
	firebase.PrintFirebaseLink()
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Sunucu başlatılamadı: %v", err)
	}
}
