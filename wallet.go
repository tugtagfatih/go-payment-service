package main

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func DepositHandler(c *gin.Context) {
	userIDString, _ := c.Get("userID")
	userID, _ := uuid.Parse(userIDString.(string)) // Hata kontrolü zaten middleware'de yapılıyor.

	var requestBody struct {
		Amount float64 `json:"amount" binding:"required,gt=0"`
	}
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// --- TRANSACTION BAŞLAT ---
	tx, err := dbPool.Begin(context.Background())
	if err != nil {
		log.Printf("Deposit tx başlatılamadı: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer tx.Rollback(context.Background())

	// Adım 1: Cüzdanı güncelle ve wallet_id'yi al.
	var walletID uuid.UUID
	var newBalance float64
	updateWalletSQL := `
		UPDATE wallets SET balance = balance + $1 
		WHERE user_id = $2 
		RETURNING id, balance`
	err = tx.QueryRow(context.Background(), updateWalletSQL, requestBody.Amount, userID).Scan(&walletID, &newBalance)
	if err != nil {
		log.Printf("Para yatırma sırasında cüzdan güncellenemedi: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not process deposit"})
		return
	}

	// Adım 2: İşlem kaydını (transaction log) oluştur.
	logTransactionSQL := `
    INSERT INTO transactions (wallet_id, type, amount, status) 
    VALUES ($1, 'deposit', $2, 'completed')` // status sütununu ve değerini ekledik
	_, err = tx.Exec(context.Background(), logTransactionSQL, walletID, requestBody.Amount)
	if err != nil {
		log.Printf("Para yatırma işlemi loglanamadı: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not log deposit transaction"})
		return
	}

	// --- TRANSACTION'I ONAYLA ---
	if err := tx.Commit(context.Background()); err != nil {
		log.Printf("Deposit tx commit edilemedi: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Deposit successful", "new_balance": newBalance})
}

func BuyListingHandler(c *gin.Context) {
	// Alıcının ID'sini middleware'den al.
	buyerIDString, _ := c.Get("userID")
	buyerID, err := uuid.Parse(buyerIDString.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid buyer ID format"})
		return
	}

	// İlan ID'sini URL'den al (örn: /api/listings/BUY-ID-HERE/buy)
	listingID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid listing ID format"})
		return
	}

	// --- ATOMİK İŞLEM İÇİN TRANSACTION BAŞLAT ---
	tx, err := dbPool.Begin(context.Background())
	if err != nil {
		log.Printf("Transaction başlatılamadı: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer tx.Rollback(context.Background())

	// Adım 1: İlanı ve satıcının bilgilerini al.
	// "FOR UPDATE", bu satırın işlem bitene kadar başka bir işlem tarafından
	// değiştirilmesini engeller (Race Condition önlemi).
	var listing Listing
	listingSQL := `SELECT id, seller_id, price, status FROM listings WHERE id = $1 FOR UPDATE`
	err = tx.QueryRow(context.Background(), listingSQL, listingID).Scan(&listing.ID, &listing.SellerID, &listing.Price, &listing.Status)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Listing not found"})
		return
	}

	// Adım 2: İş kurallarını kontrol et.
	if listing.Status != "active" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "This item is not available for sale"})
		return
	}
	if listing.SellerID == buyerID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "You cannot buy your own item"})
		return
	}

	// Adım 3: Alıcının cüzdanını kontrol et. Yine "FOR UPDATE" ile kilitliyoruz.
	var buyerBalance float64
	walletSQL := `SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE`
	err = tx.QueryRow(context.Background(), walletSQL, buyerID).Scan(&buyerBalance)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not retrieve buyer wallet"})
		return
	}

	if buyerBalance < listing.Price {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Insufficient funds"})
		return
	}

	// Adım 4: Alıcının ve Satıcının cüzdan ID'lerini al.
	var buyerWalletID, sellerWalletID uuid.UUID
	tx.QueryRow(context.Background(), `SELECT id FROM wallets WHERE user_id = $1`, buyerID).Scan(&buyerWalletID)
	tx.QueryRow(context.Background(), `SELECT id FROM wallets WHERE user_id = $1`, listing.SellerID).Scan(&sellerWalletID)

	// Adım 5: Bakiyeleri güncelle.
	// Alıcının bakiyesini düşür.
	_, err = tx.Exec(context.Background(), `UPDATE wallets SET balance = balance - $1 WHERE id = $2`, listing.Price, buyerWalletID)
	if err != nil { /* ... hata kontrolü ... */
	}

	// Satıcının bakiyesini artır.
	_, err = tx.Exec(context.Background(), `UPDATE wallets SET balance = balance + $1 WHERE id = $2`, listing.Price, sellerWalletID)
	if err != nil { /* ... hata kontrolü ... */
	}

	// YENİ Adım 6: İşlem kayıtlarını oluştur.
	// Alıcı için 'purchase' kaydı.
	logPurchaseSQL := `
    INSERT INTO transactions (wallet_id, type, amount, related_listing_id) 
    VALUES ($1, 'purchase', $2, $3)`
	_, err = tx.Exec(context.Background(), logPurchaseSQL, buyerWalletID, -listing.Price, listingID) // Tutar negatif
	if err != nil {                                                                                  /* ... hata kontrolü ... */
	}

	// Satıcı için 'sale' kaydı.
	logSaleSQL := `
    INSERT INTO transactions (wallet_id, type, amount, related_listing_id) 
    VALUES ($1, 'sale', $2, $3)`
	_, err = tx.Exec(context.Background(), logSaleSQL, sellerWalletID, listing.Price, listingID) // Tutar pozitif
	if err != nil {                                                                              /* ... hata kontrolü ... */
	}

	// Adım 5: İlanın durumunu 'sold' olarak güncelle.
	updateListingSQL := `UPDATE listings SET status = 'sold' WHERE id = $1`
	_, err = tx.Exec(context.Background(), updateListingSQL, listingID)
	if err != nil {
		log.Printf("İlan durumu güncellenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Transaction failed"})
		return
	}

	// --- HER ŞEY YOLUNDA, TRANSACTION'I ONAYLA (COMMIT) ---
	if err := tx.Commit(context.Background()); err != nil {
		log.Printf("Transaction commit edilemedi: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during purchase"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Purchase successful!"})
}

func GetTransactionHistoryHandler(c *gin.Context) {
	// Adım 1: Kullanıcı ID'sini AuthMiddleware'den al.
	userIDString, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
		return
	}

	userID, err := uuid.Parse(userIDString.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	// Adım 2: Kullanıcının cüzdan ID'sini bul.
	var walletID uuid.UUID
	walletSQL := `SELECT id FROM wallets WHERE user_id = $1`
	err = dbPool.QueryRow(context.Background(), walletSQL, userID).Scan(&walletID)
	if err != nil {
		// "no rows in result set" hatası, kullanıcıya ait bir cüzdan bulunamadığı anlamına gelir.
		// Bu normalde olmamalı (çünkü register'da oluşturuyoruz) ama kontrol etmek iyidir.
		log.Printf("Kullanıcı %s için cüzdan bulunamadı: %v", userID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Wallet not found for the user"})
		return
	}

	// Adım 3: Bulunan cüzdan ID'si ile tüm işlemleri çek.
	transactionsSQL := `
		SELECT id, wallet_id, type, amount, related_listing_id, created_at 
		FROM transactions 
		WHERE wallet_id = $1 
		ORDER BY created_at DESC`

	rows, err := dbPool.Query(context.Background(), transactionsSQL, walletID)
	if err != nil {
		log.Printf("İşlem geçmişi sorgulanırken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch transaction history"})
		return
	}
	defer rows.Close()

	// Adım 4: Dönen satırları işle ve bir listeye doldur.
	transactions := make([]Transaction, 0)
	for rows.Next() {
		var t Transaction
		// Scan fonksiyonundaki değişkenlerin sırası, SELECT sorgusundaki sütunların sırasıyla
		// birebir aynı olmalıdır.
		if err := rows.Scan(&t.ID, &t.WalletID, &t.Type, &t.Amount, &t.RelatedListingID, &t.CreatedAt); err != nil {
			log.Printf("İşlem satırı okunurken hata: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error processing transaction data"})
			return
		}
		transactions = append(transactions, t)
	}

	// Döngü bittikten sonra bir hata olup olmadığını son bir kez kontrol et.
	if err := rows.Err(); err != nil {
		log.Printf("İşlem geçmişi okunurken satır hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reading transaction history"})
		return
	}

	// Adım 5: Sonucu JSON olarak döndür.
	// Eğer hiç işlem yoksa, boş bir liste `[]` dönecektir, bu bir hata değildir.
	c.JSON(http.StatusOK, transactions)
}
