package database

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Connect, verilen DSN (Data Source Name) ile veritabanına bağlanır
// ve bir bağlantı havuzu döndürür.
func Connect(dsn string) (*pgxpool.Pool, error) {
	dbPool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return nil, fmt.Errorf("veritabanına bağlanılamadı: %w", err)
	}

	if err := dbPool.Ping(context.Background()); err != nil {
		dbPool.Close() // Ping başarısız olursa bağlantıyı kapat.
		return nil, fmt.Errorf("veritabanına ping atılamadı: %w", err)
	}

	log.Println("Veritabanı bağlantısı başarılı!")
	return dbPool, nil
}
