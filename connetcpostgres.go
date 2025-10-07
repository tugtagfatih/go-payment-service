package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

func ConnectPosgres() {
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

	if err := dbPool.Ping(context.Background()); err != nil {
		log.Fatalf("Veritabanına ping atılamadı: %v\n", err)
	}
	log.Println("Veritabanı bağlantısı başarılı!")

}
