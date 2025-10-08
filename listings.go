package main

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func CreateListingHandler(c *gin.Context) {
	// 1. İstek body'sini parse et.
	var requestBody struct {
		ItemName    string  `json:"item_name" binding:"required"`
		Description string  `json:"description"`
		Price       float64 `json:"price" binding:"required,gte=0"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 2. Satıcı kim? AuthMiddleware'in context'e eklediği userID'yi al.
	// Bu, ilanı kimin oluşturduğunu bilmemizi sağlar.
	sellerIDString, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
		return
	}

	sellerID, err := uuid.Parse(sellerIDString.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	// 3. Veritabanına yeni ilanı ekle.
	sql := `
		INSERT INTO listings (seller_id, item_name, description, price) 
		VALUES ($1, $2, $3, $4) 
		RETURNING id, status, created_at`

	var newListing Listing
	err = dbPool.QueryRow(
		context.Background(), sql,
		sellerID, requestBody.ItemName, requestBody.Description, requestBody.Price,
	).Scan(&newListing.ID, &newListing.Status, &newListing.CreatedAt)

	if err != nil {
		log.Printf("İlan eklenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create listing"})
		return
	}

	// Eksik bilgileri tamamlayıp kullanıcıya geri dönelim.
	newListing.SellerID = sellerID
	newListing.ItemName = requestBody.ItemName
	newListing.Description = requestBody.Description
	newListing.Price = requestBody.Price

	c.JSON(http.StatusCreated, newListing)
}

// ListListingsHandler, herkesin aktif ilanları görmesini sağlar.
func ListListingsHandler(c *gin.Context) {
	sql := `SELECT id, seller_id, item_name, description, price, status, created_at 
			FROM listings 
			WHERE status = 'active' ORDER BY created_at DESC`

	rows, err := dbPool.Query(context.Background(), sql)
	if err != nil {
		log.Printf("İlanlar listelenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch listings"})
		return
	}
	defer rows.Close()

	listings := make([]Listing, 0)
	for rows.Next() {
		var l Listing
		if err := rows.Scan(&l.ID, &l.SellerID, &l.ItemName, &l.Description, &l.Price, &l.Status, &l.CreatedAt); err != nil {
			log.Printf("İlan satırı okunurken hata: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error processing listing data"})
			return
		}
		listings = append(listings, l)
	}

	if err := rows.Err(); err != nil {
		log.Printf("İlanları listelerken satır hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reading listing list"})
		return
	}

	c.JSON(http.StatusOK, listings)
}
