package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. İstek başlığından (header) Authorization değerini al.
		// Format: "Bearer TOKEN_STRING"
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
			return
		}

		// "Bearer " kısmını ayıklayarak sadece token'ı alıyoruz.
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			return
		}

		// 2. Token'ı parse et ve doğrula.
		claims := &jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			// İmzalama metodunun beklediğimiz gibi (HS256) olup olmadığını kontrol et.
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecretKey, nil
		})

		// 3. Token geçersizse veya bir hata oluştuysa, isteği reddet.
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			return
		}

		// 4. Token geçerliyse, kullanıcı ID'sini context'e ekle.
		// Bu sayede sonraki handler fonksiyonu bu bilgiye erişebilir.
		c.Set("userID", claims.Subject)

		// 5. İsteğin bir sonraki adıma (asıl handler fonksiyonuna) geçmesine izin ver.
		c.Next()
	}
}
