package handlers

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tugtagfatih/go-payment-service/internal/auth"
	"github.com/tugtagfatih/go-payment-service/internal/models"
	"golang.org/x/crypto/bcrypt"
)

// Handler, tüm handler fonksiyonlarımız için bir "alıcı" (receiver) görevi görecek.
// Bu struct, veritabanı bağlantısı gibi bağımlılıkları tutar.
type Handler struct {
	DB   *pgxpool.Pool
	Auth *auth.Auth
}

func NewHandler(db *pgxpool.Pool, auth *auth.Auth) *Handler {
	return &Handler{
		DB:   db,
		Auth: auth,
	}
}

func (h *Handler) RegisterUserHandler(c *gin.Context) {
	var requestBody struct {
		Username string `json:"username" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(requestBody.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	tx, err := h.DB.Begin(context.Background())
	if err != nil {
		log.Printf("Transaction başlatılamadı: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer tx.Rollback(context.Background())

	userSQL := `INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id`
	var userID uuid.UUID
	err = tx.QueryRow(context.Background(), userSQL, requestBody.Username, requestBody.Email, string(hashedPassword)).Scan(&userID)
	if err != nil {
		log.Printf("Kullanıcı eklenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create user"})
		return
	}

	walletSQL := `INSERT INTO wallets (user_id) VALUES ($1)`
	_, err = tx.Exec(context.Background(), walletSQL, userID)
	if err != nil {
		log.Printf("Cüzdan oluşturulurken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create user wallet"})
		return
	}

	if err := tx.Commit(context.Background()); err != nil {
		log.Printf("Transaction commit edilemedi: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during user creation"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully with a wallet", "userID": userID})
}

func (h *Handler) LoginHandler(c *gin.Context) {
	var requestBody struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	sql := `SELECT id, password_hash FROM users WHERE email = $1`
	err := h.DB.QueryRow(context.Background(), sql, requestBody.Email).Scan(&user.ID, &user.PasswordHash)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(requestBody.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	tokenString, err := h.Auth.GenerateJWT(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func (h *Handler) CreateListingHandler(c *gin.Context) {
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

	var newListing models.Listing
	err = h.DB.QueryRow(
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

func (h *Handler) ListListingsHandler(c *gin.Context) {
	sql := `SELECT id, seller_id, item_name, description, price, status, created_at 
			FROM listings 
			WHERE status = 'active' ORDER BY created_at DESC`

	rows, err := h.DB.Query(context.Background(), sql)
	if err != nil {
		log.Printf("İlanlar listelenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch listings"})
		return
	}
	defer rows.Close()

	listings := make([]models.Listing, 0)
	for rows.Next() {
		var l models.Listing
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

func (h *Handler) ProfileHandler(c *gin.Context) {
	// AuthMiddleware'den gelen userID'yi alıyoruz.
	// c.Get() bir interface{} döndürdüğü için tip dönüşümü (type assertion) yapmamız gerekebilir.
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
		return
	}

	// TODO: Bu userID ile veritabanından kullanıcının tüm bilgilerini
	// (username, email, balance vb.) çekip döndürebilirsin.
	// Şimdilik sadece ID'yi döndürelim.

	c.JSON(http.StatusOK, gin.H{
		"message": "Welcome to your profile!",
		"user_id": userID,
	})
}

func (h *Handler) GetWalletHandler(c *gin.Context) {
	userIDString, _ := c.Get("userID")
	userID, err := uuid.Parse(userIDString.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	var wallet models.Wallet
	sql := `SELECT id, user_id, balance, currency, created_at FROM wallets WHERE user_id = $1`
	err = h.DB.QueryRow(context.Background(), sql, userID).Scan(&wallet.ID, &wallet.UserID, &wallet.Balance, &wallet.Currency, &wallet.CreatedAt)
	if err != nil {
		// Eğer cüzdan bulunamazsa (bir hata sonucu oluşmamışsa)
		if err.Error() == "no rows in result set" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Wallet not found for this user"})
			return
		}
		log.Printf("Cüzdan aranırken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch wallet information"})
		return
	}

	c.JSON(http.StatusOK, wallet)
}

func (h *Handler) DepositHandler(c *gin.Context) {
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
	tx, err := h.DB.Begin(context.Background())
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

func (h *Handler) BuyListingHandler(c *gin.Context) {
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
	tx, err := h.DB.Begin(context.Background())
	if err != nil {
		log.Printf("Transaction başlatılamadı: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer tx.Rollback(context.Background())

	// Adım 1: İlanı ve satıcının bilgilerini al.
	// "FOR UPDATE", bu satırın işlem bitene kadar başka bir işlem tarafından
	// değiştirilmesini engeller (Race Condition önlemi).
	var listing models.Listing
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

func (h *Handler) GetTransactionHistoryHandler(c *gin.Context) {
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
	err = h.DB.QueryRow(context.Background(), walletSQL, userID).Scan(&walletID)
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

	rows, err := h.DB.Query(context.Background(), transactionsSQL, walletID)
	if err != nil {
		log.Printf("İşlem geçmişi sorgulanırken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch transaction history"})
		return
	}
	defer rows.Close()

	// Adım 4: Dönen satırları işle ve bir listeye doldur.
	transactions := make([]models.Transaction, 0)
	for rows.Next() {
		var t models.Transaction
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
