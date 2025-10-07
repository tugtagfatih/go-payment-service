package main

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

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

func LoginHandler(c *gin.Context){
	var requestBody struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sql := `SELECT id, password_hash FROM users WHERE email = $1`
	var userID uuid.UUID
	var passwordHash string
	err := dbPool.QueryRow(context.Background(), sql, requestBody.Email).Scan(&userID, &passwordHash)
	if err != nil {
		log.Printf("Kullanıcı bulunamadı: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if !CheckPasswordHash(requestBody.Password, passwordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "userID": userID})
}
