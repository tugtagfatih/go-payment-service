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
	//config.AllowOrigins = []string{"http://localhost:5173"}
	config.AllowAllOrigins = true
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Authorization"}
	router.Use(cors.New(config))

	publicRoutes := router.Group("/")
	{
		authGroup := publicRoutes.Group("/auth")
		{
			authGroup.POST("/register", h.RegisterUserHandler)
			authGroup.POST("/login", h.LoginHandler)
		}
		publicRoutes.GET("/listings", h.ListListingsHandler)
		publicRoutes.GET("/listings/:id", h.GetListingByIDHandler)
	}

	// Korumalı (Protected) KULLANICI Rotaları
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

		listingsGroup := api.Group("/listings")
		{
			listingsGroup.POST("", h.CreateListingHandler)
			listingsGroup.POST("/:id/buy", h.BuyListingHandler)
		}
	}

	// Korumalı (Protected) ADMİN Rotaları (AYRI BİR GRUP)
	adminRoutes := router.Group("/admin")
	adminRoutes.Use(authService.Middleware(), authService.RoleMiddleware("approver", "admin", "master_admin"))
	{
		adminRoutes.GET("/notifications", h.ListPaymentNotificationsHandler)
		adminRoutes.POST("/notifications/:id/reject", h.RejectPaymentNotificationHandler)
		adminRoutes.POST("/notifications/:id/approve", h.ApprovePaymentNotificationHandler)

		adminRoutes.GET("/withdrawals", h.ListWithdrawalRequestsHandler)
		adminRoutes.POST("/withdrawals/:id/approve", h.ApproveWithdrawalRequestHandler)
		adminRoutes.POST("/withdrawals/:id/reject", h.RejectPaymentNotificationHandler)

		adminRoutes.GET("/users", authService.RoleMiddleware("admin", "master_admin"), h.ListUsersHandler)
		adminRoutes.POST("/users/:id/ban", authService.RoleMiddleware("admin", "master_admin"), h.BanUserHandler)
		adminRoutes.POST("/users/:id/unban", authService.RoleMiddleware("admin", "master_admin"), h.UnbanUserHandler)

		adminRoutes.PUT("/users/:id/role", authService.RoleMiddleware("admin", "master_admin"), h.UpdateUserRoleHandler)

		adminRoutes.GET("/manageable-users", authService.RoleMiddleware("admin", "master_admin"), h.ListManageableUsersHandler)
	}

	// Korumalı (Protected) MASTER ADMİN Rotaları (AYRI BİR GRUP)
	masterAdminRoutes := router.Group("/master-admin")
	masterAdminRoutes.Use(authService.Middleware(), authService.RoleMiddleware("master_admin"))
	{
		masterAdminRoutes.POST("/users/:id/grant-admin", h.GrantAdminHandler)
	}

	// 6. Sunucuyu Başlat
	log.Println("Sunucu 8080 portunda başlatılıyor...")
	firebase.PrintFirebaseLink()
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Sunucu başlatılamadı: %v", err)
	}
}
