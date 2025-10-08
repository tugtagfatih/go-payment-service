package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

// Config struct'ı, uygulamamızın ihtiyaç duyduğu tüm ayarları barındırır.
type Config struct {
	DBUser       string
	DBPassword   string
	DBHost       string
	DBPort       string
	DBName       string
	JWTSecretKey string
	DSN          string // Data Source Name (Veritabanı bağlantı adresi)
}

// LoadConfig, belirtilen yoldaki .env dosyasını okur ve Config struct'ını doldurur.
func LoadConfig(path string) (*Config, error) {
	if err := godotenv.Load(path); err != nil {
		return nil, fmt.Errorf("error loading .env file: %w", err)
	}

	cfg := &Config{
		DBUser:       os.Getenv("POSTGRES_USER"),
		DBPassword:   os.Getenv("POSTGRES_PASSWORD"),
		DBHost:       os.Getenv("POSTGRES_HOST"),
		DBPort:       os.Getenv("POSTGRES_PORT"),
		DBName:       os.Getenv("POSTGRES_DB"),
		JWTSecretKey: os.Getenv("JWT_SECRET_KEY"),
	}

	// DSN'i burada, tüm bilgiler bir aradayken oluşturmak daha temizdir.
	cfg.DSN = fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
		cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName)

	return cfg, nil
}
