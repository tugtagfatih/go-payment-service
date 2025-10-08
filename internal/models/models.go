package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	CreatedAt    time.Time `json:"created_at"`
	PasswordHash string    `json:"-"`
}

type Listing struct {
	ID          uuid.UUID `json:"id"`
	SellerID    uuid.UUID `json:"seller_id"`
	ItemName    string    `json:"item_name"`
	Description string    `json:"description"`
	Price       float64   `json:"price"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

type Wallet struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	Balance   float64   `json:"balance"`
	Currency  string    `json:"currency"`
	CreatedAt time.Time `json:"created_at"`
}

type Transaction struct {
	ID               uuid.UUID  `json:"id"`
	WalletID         uuid.UUID  `json:"wallet_id"`
	Type             string     `json:"type"`
	Amount           float64    `json:"amount"`
	RelatedListingID *uuid.UUID `json:"related_listing_id,omitempty"` // Null olabilir
	CreatedAt        time.Time  `json:"created_at"`
}

type PaymentNotification struct {
	ID          uuid.UUID  `json:"id"`
	UserID      uuid.UUID  `json:"user_id"`
	Amount      float64    `json:"amount"`
	Status      string     `json:"status"`
	Notes       *string    `json:"notes,omitempty"` // Null olabilir
	CreatedAt   time.Time  `json:"created_at"`
	ReviewedBy  *uuid.UUID `json:"reviewed_by,omitempty"` // Null olabilir
	ReviewedAt  *time.Time `json:"reviewed_at,omitempty"` // Null olabilir
}