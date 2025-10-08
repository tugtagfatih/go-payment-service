package auth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Auth struct'ı, JWT işlemleri için gerekli olan gizli anahtar gibi
// bağımlılıkları tutar.
type Auth struct {
	SecretKey []byte
}

// NewAuth, yeni bir Auth servisi oluşturur ve başlatır.
func NewAuth(secretKey string) (*Auth, error) {
	if secretKey == "" {
		return nil, fmt.Errorf("JWT secret key cannot be empty")
	}
	return &Auth{SecretKey: []byte(secretKey)}, nil
}

// GenerateJWT, belirtilen bir kullanıcı ID'si için yeni bir JWT oluşturur ve imzalar.
func (a *Auth) GenerateJWT(userID uuid.UUID) (string, error) {
	// Token'ın geçerlilik süresini 24 saat olarak ayarlıyoruz.
	expirationTime := time.Now().Add(24 * time.Hour)

	// Token'ın "payload" kısmına koyacağımız bilgileri (claims) hazırlıyoruz.
	// Subject (konu) olarak kullanıcının ID'sini kullanmak yaygın bir yöntemdir.
	claims := &jwt.RegisteredClaims{
		Subject:   userID.String(),
		ExpiresAt: jwt.NewNumericDate(expirationTime),
	}

	// Token'ı HS256 imzalama algoritması ve hazırladığımız claim'lerle oluşturuyoruz.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Token'ı gizli anahtarımızla imzalayarak son haline getiriyoruz.
	tokenString, err := token.SignedString(a.SecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Middleware, gelen istekte geçerli bir JWT olup olmadığını kontrol eden bir Gin middleware'i döndürür.
func (a *Auth) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// İstek başlığından (header) "Authorization" değerini al.
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
			return
		}

		// Header'ın "Bearer TOKEN_STRING" formatında olup olmadığını kontrol et.
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			return
		}

		// Token'ı parse et ve doğrula.
		claims := &jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			// İmzalama metodunun, token'ı bizim oluştururken kullandığımız
			// metot (HMAC) olup olmadığını kontrol etmek önemlidir.
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			// Doğrulama için gizli anahtarımızı döndür.
			return a.SecretKey, nil
		})

		// Eğer token geçersizse (süresi dolmuş, imza yanlış vb.) veya bir hata oluştuysa isteği reddet.
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			return
		}

		// Token geçerliyse, sonraki handler'ların kullanabilmesi için kullanıcı ID'sini context'e ekle.
		c.Set("userID", claims.Subject)

		// Her şey yolunda, isteğin bir sonraki adıma geçmesine izin ver.
		c.Next()
	}
}
