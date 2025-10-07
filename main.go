package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

var dbPool *pgxpool.Pool

type User struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	Balance      float64   `json:"balance"`
	CreatedAt    time.Time `json:"created_at"`
	PasswordHash string    `json:"-"`
}

func main() {
	fmt.Println("https://localhost:8080")
	// 1. .env dosyasını yükle
	// Bu fonksiyonu main fonksiyonunun en başına koymak en iyi pratiktir.
	err := godotenv.Load("postgres.env") // Dosya adını belirtiyoruz
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// 2. Değişkenleri os.Getenv ile oku
	dbUser := os.Getenv("POSTGRES_USERNAME")
	dbPassword := os.Getenv("POSTGRES_PASSWORD")
	dbHost := os.Getenv("POSTGRES_HOSTNAME")
	dbPort := os.Getenv("POSTGRES_PORT")
	dbName := os.Getenv("POSTGRES_DB")

	// Eğer değişkenlerden biri boşsa, programı durdur.
	if dbUser == "" || dbPassword == "" || dbHost == "" || dbPort == "" || dbName == "" {
		log.Fatal("Database environment variables are not set correctly")
	}

	// Veritabanı bağlantı adresi (DSN)
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", dbUser, dbPassword, dbHost, dbPort, dbName)

	// Veritabanına bağlan
	dbPool, err = pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("Veritabanına bağlanılamadı: %v\n", err)
	}
	defer dbPool.Close()

	if err := dbPool.Ping(context.Background()); err != nil {
		log.Fatalf("Veritabanına ping atılamadı: %v\n", err)
	}
	log.Println("Veritabanı bağlantısı başarılı!")

	router := gin.Default()

	userRoutes := router.Group("/users")
	{
		userRoutes.POST("", RegisterUserHandler)
		userRoutes.GET("", ListUsersHandler)
	}

	log.Println("Sunucu 8080 portunda başlatılıyor...")
	router.Run(":8080")
}

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

func PingHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "pong from the new structure",
	})
}

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

	// TODO: Şifreyi kaydetmeden önce BCRYPT ile hash'le!
	passwordHash, _ := HashPassword(requestBody.Password)

	sql := `INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id`
	var userID uuid.UUID
	err := dbPool.QueryRow(context.Background(), sql, requestBody.Username, requestBody.Email, passwordHash).Scan(&userID)
	if err != nil {
		log.Printf("Kullanıcı eklenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create user"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully", "userID": userID})
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

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
