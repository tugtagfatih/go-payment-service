package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func RegisterUserHandler(c *gin.Context) {
	var requestBody struct {
		Username string `json:"username" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(requestBody.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// --- VERİTABANI TRANSACTION'I BAŞLAT ---
	tx, err := dbPool.Begin(context.Background())
	if err != nil {
		log.Printf("Transaction başlatılamadı: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	// `defer` ile, fonksiyondan çıkılmadan önce transaction'ın geri alınmasını garantiliyoruz.
	// Eğer işlem başarılı olursa, bu `Rollback` bir işe yaramayacak çünkü öncesinde `Commit` edeceğiz.
	defer tx.Rollback(context.Background())

	// Adım 1: Yeni kullanıcıyı oluştur.
	userSQL := `INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id`
	var userID uuid.UUID
	err = tx.QueryRow(context.Background(), userSQL, requestBody.Username, requestBody.Email, string(hashedPassword)).Scan(&userID)
	if err != nil {
		log.Printf("Kullanıcı eklenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create user"})
		return
	}

	// Adım 2: O kullanıcı için bir cüzdan oluştur.
	walletSQL := `INSERT INTO wallets (user_id) VALUES ($1)`
	_, err = tx.Exec(context.Background(), walletSQL, userID)
	if err != nil {
		log.Printf("Cüzdan oluşturulurken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create user wallet"})
		return
	}

	// --- HER ŞEY YOLUNDAYSA TRANSACTION'I ONAYLA (COMMIT) ---
	if err := tx.Commit(context.Background()); err != nil {
		log.Printf("Transaction commit edilemedi: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during user creation"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully with a wallet", "userID": userID})
}

func ListUsersHandler(c *gin.Context) {
	sql := `SELECT id, username, email, created_at FROM users`
	rows, err := dbPool.Query(context.Background(), sql)
	if err != nil {
		log.Printf("Kullanıcıları listelerken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch users"})
		return
	}
	defer rows.Close()

	users := make([]User, 0)
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.CreatedAt); err != nil {
			log.Printf("Kullanıcı satırı okunurken hata: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error processing user data"})
			return
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		log.Printf("Kullanıcıları listelerken satır hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reading user list"})
		return
	}
	c.JSON(http.StatusOK, users)
}

func LoginHandler(c *gin.Context) {
	var requestBody struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var user User
	sql := `SELECT id, username, email, password_hash FROM users WHERE email = $1`
	err := dbPool.QueryRow(context.Background(), sql, requestBody.Email).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(requestBody.Password))
	if err != nil {
		// Eğer şifreler eşleşmezse, bcrypt hata döner.
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &jwt.RegisteredClaims{
		Subject:   user.ID.String(), // Genellikle kullanıcının ID'si konur
		ExpiresAt: jwt.NewNumericDate(expirationTime),
	}

	// Token'ı oluştur ve gizli anahtarımızla imzala.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// 4. Adım: Token'ı kullanıcıya geri dön.
	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
	})
}

func ProfileHandler(c *gin.Context) {
	// AuthMiddleware'den gelen userID'yi alıyoruz.
	// c.Get() bir interface{} döndürdüğü için tip dönüşümü (type assertion) yapmamız gerekebilir.
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
		return
	}

	// TODO: Bu userID ile veritabanından kullanıcının tüm bilgilerini
	// (username, email, balance vb.) çekip döndürebilirsin.
	// Şimdilik sadece ID'yi döndürelim.

	c.JSON(http.StatusOK, gin.H{
		"message": "Welcome to your profile!",
		"user_id": userID,
	})
}

func GetWalletHandler(c *gin.Context) {
	userIDString, _ := c.Get("userID")
	userID, err := uuid.Parse(userIDString.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	var wallet Wallet
	sql := `SELECT id, user_id, balance, currency, created_at FROM wallets WHERE user_id = $1`
	err = dbPool.QueryRow(context.Background(), sql, userID).Scan(&wallet.ID, &wallet.UserID, &wallet.Balance, &wallet.Currency, &wallet.CreatedAt)
	if err != nil {
		// Eğer cüzdan bulunamazsa (bir hata sonucu oluşmamışsa)
		if err.Error() == "no rows in result set" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Wallet not found for this user"})
			return
		}
		log.Printf("Cüzdan aranırken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch wallet information"})
		return
	}

	c.JSON(http.StatusOK, wallet)
}
