package handlers

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
	// DÖRT sütun seçiyoruz: id, password_hash, role, account_status
	sql := `SELECT id, username, email, password_hash, role, account_status FROM users WHERE email = $1`

	// Ve DÖRT değişkene okuyoruz: &user.ID, &user.PasswordHash, &user.Role, &user.AccountStatus
	err := h.DB.QueryRow(context.Background(), sql, requestBody.Email).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Role, &user.AccountStatus)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	// Banlı kullanıcı kontrolü
	if user.AccountStatus == "banned" {
		c.JSON(http.StatusForbidden, gin.H{"error": "This account has been banned."})
		return
	}

	// Şifre karşılaştırma
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(requestBody.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	// JWT oluşturma
	tokenString, err := h.Auth.GenerateJWT(user.ID, user.Role, user.Username, user.Email)
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

	// Kullanıcının bilgilerini veritabanından çekiyoruz.
	var user models.User
	sql := `SELECT id, username, email, iban, withdrawal_bank_name FROM users WHERE id = $1`                                                 // withdrawal_bank_name eklendi
	err = h.DB.QueryRow(context.Background(), sql, userID).Scan(&user.ID, &user.Username, &user.Email, &user.IBAN, &user.WithdrawalBankName) // Scan içine eklendi
	if err != nil {
		log.Printf("Profil bilgileri alınırken hata: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User profile not found"})
		return
	}

	// Şifre hash'i gibi hassas bilgileri göndermeden sadece gerekli bilgileri döndürüyoruz.
	c.JSON(http.StatusOK, gin.H{
		"id":                   user.ID,
		"username":             user.Username,
		"email":                user.Email,
		"iban":                 user.IBAN,
		"withdrawal_bank_name": user.WithdrawalBankName, // YENİ EKLENDİ
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

// internal/handlers/handlers.go dosyasındaki BuyListingHandler fonksiyonu

func (h *Handler) BuyListingHandler(c *gin.Context) {
	buyerIDString, _ := c.Get("userID")
	buyerID, _ := uuid.Parse(buyerIDString.(string))

	listingID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid listing ID format"})
		return
	}

	tx, err := h.DB.Begin(context.Background())
	if err != nil {
		log.Printf("Buy tx başlatılamadı: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer tx.Rollback(context.Background())

	var listing models.Listing
	listingSQL := `SELECT id, seller_id, price, status FROM listings WHERE id = $1 FOR UPDATE`
	err = tx.QueryRow(context.Background(), listingSQL, listingID).Scan(&listing.ID, &listing.SellerID, &listing.Price, &listing.Status)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Listing not found"})
		return
	}

	if listing.Status != "active" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "This item is not available for sale"})
		return
	}
	if listing.SellerID == buyerID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "You cannot buy your own item"})
		return
	}

	var buyerBalance float64
	walletSQL := `SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE`
	err = tx.QueryRow(context.Background(), walletSQL, buyerID).Scan(&buyerBalance)
	if err != nil {
		log.Printf("Alıcının cüzdanı bulunamadı: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not retrieve buyer wallet"})
		return
	}

	if buyerBalance < listing.Price {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Insufficient funds"})
		return
	}

	// --- Alıcı bakiyesini güncelle ---
	updateBuyerSQL := `UPDATE wallets SET balance = balance - $1 WHERE user_id = $2`
	_, err = tx.Exec(context.Background(), updateBuyerSQL, listing.Price, buyerID)
	if err != nil {
		log.Printf("Alıcı bakiyesi güncellenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Transaction failed at buyer update"})
		return // ÖNEMLİ: Hata varsa işlemi durdur
	}

	// --- Satıcı bakiyesini güncelle ---
	updateSellerSQL := `UPDATE wallets SET balance = balance + $1 WHERE user_id = $2`
	_, err = tx.Exec(context.Background(), updateSellerSQL, listing.Price, listing.SellerID)
	if err != nil {
		log.Printf("Satıcı bakiyesi güncellenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Transaction failed at seller update"})
		return // ÖNEMLİ: Hata varsa işlemi durdur
	}

	// --- İşlem kayıtlarını oluştur ---
	// (Bu kısmı önceki adımdan kopyalayıp hata kontrollerini ekleyin)
	// ...

	// --- İlan durumunu güncelle ---
	updateListingSQL := `UPDATE listings SET status = 'sold' WHERE id = $1`
	_, err = tx.Exec(context.Background(), updateListingSQL, listingID)
	if err != nil {
		log.Printf("İlan durumu güncellenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Transaction failed at listing update"})
		return // ÖNEMLİ: Hata varsa işlemi durdur
	}

	if err := tx.Commit(context.Background()); err != nil {
		log.Printf("Buy tx commit edilemedi: %v", err)
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
		SELECT id, wallet_id, type, amount, status, related_listing_id, created_at 
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
		// Scan fonksiyonuna &t.Status eklendi
		if err := rows.Scan(&t.ID, &t.WalletID, &t.Type, &t.Amount, &t.Status, &t.RelatedListingID, &t.CreatedAt); err != nil {
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

func (h *Handler) CreatePaymentNotificationHandler(c *gin.Context) {
	ctx := c.Request.Context() // Context güncellendi
	userIDString, _ := c.Get("userID")
	userID, _ := uuid.Parse(userIDString.(string))

	var requestBody struct {
		Amount        float64    `json:"amount" binding:"required,gt=0"`
		Notes         *string    `json:"notes"`                              // Artık pointer
		DepositBankID *uuid.UUID `json:"deposit_bank_id" binding:"required"` // YENİ EKLENDİ, zorunlu
		SenderName    *string    `json:"sender_name" binding:"required"`     // YENİ EKLENDİ, zorunlu
	}
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Seçilen bankanın aktif olup olmadığını kontrol et (güvenlik için)
	var isActive bool
	var bankExists bool
	err := h.DB.QueryRow(ctx, "SELECT is_active FROM deposit_banks WHERE id = $1", requestBody.DepositBankID).Scan(&isActive)
	if err == nil {
		bankExists = true
	} else if err != pgx.ErrNoRows { // Sorgu hatası varsa logla
		log.Printf("Ödeme bildirimi için banka kontrolü sırasında hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not verify deposit bank"})
		return
	}

	if !bankExists || !isActive {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Selected bank is not valid or not active."})
		return
	}

	sql := `
		INSERT INTO payment_notifications (user_id, amount, notes, deposit_bank_id, sender_name)
		VALUES ($1, $2, $3, $4, $5)`

	_, err = h.DB.Exec(ctx, sql, userID, requestBody.Amount, requestBody.Notes, requestBody.DepositBankID, requestBody.SenderName) // Context ve yeni alanlar eklendi
	if err != nil {
		log.Printf("Ödeme bildirimi oluşturulurken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create payment notification"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Payment notification received. It will be reviewed by an administrator."})
}

// ApprovePaymentNotificationHandler, bir adminin ödeme bildirimini onaylamasını simüle eder.
func (h *Handler) ApprovePaymentNotificationHandler(c *gin.Context) {
	notificationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid notification ID format"})
		return
	}

	tx, err := h.DB.Begin(context.Background())
	if err != nil {
		log.Printf("Admin onay tx başlatılamadı: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer tx.Rollback(context.Background())

	// Adım 1: Bildirimi al ve 'pending' durumunda olduğundan emin ol.
	var notification models.PaymentNotification
	var walletID uuid.UUID
	selectSQL := `
		SELECT pn.id, pn.user_id, pn.amount, pn.status, w.id as wallet_id
		FROM payment_notifications pn
		JOIN wallets w ON pn.user_id = w.user_id
		WHERE pn.id = $1 FOR UPDATE`

	err = tx.QueryRow(context.Background(), selectSQL, notificationID).Scan(&notification.ID, &notification.UserID, &notification.Amount, &notification.Status, &walletID)
	if err != nil {
		log.Printf("Onaylanacak bildirim bulunamadı veya sorgu hatası: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Payment notification not found"})
		return // ÖNEMLİ: Hata varsa fonksiyondan çık
	}
	if notification.Status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "This notification has already been processed."})
		return
	}

	// Adım 2: Kullanıcının cüzdan bakiyesini güncelle.
	updateWalletSQL := `UPDATE wallets SET balance = balance + $1 WHERE id = $2`
	_, err = tx.Exec(context.Background(), updateWalletSQL, notification.Amount, walletID)
	if err != nil {
		log.Printf("Onay sırasında cüzdan güncellenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update wallet"})
		return // ÖNEMLİ: Hata varsa fonksiyondan çık
	}

	// Adım 3: İşlem kaydını (transaction log) oluştur.
	logTransactionSQL := `INSERT INTO transactions (wallet_id, type, amount, status) VALUES ($1, 'deposit', $2, 'completed')` // status sütununu ve değerini ekledik
	_, err = tx.Exec(context.Background(), logTransactionSQL, walletID, notification.Amount)
	if err != nil {
		log.Printf("Onay sırasında işlem loglanırken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to log transaction"})
		return // ÖNEMLİ: Hata varsa fonksiyondan çık
	}

	// Adım 4: Ödeme bildiriminin durumunu 'approved' olarak güncelle.
	updateNotificationSQL := `UPDATE payment_notifications SET status = 'approved' WHERE id = $1`
	_, err = tx.Exec(context.Background(), updateNotificationSQL, notificationID)
	if err != nil {
		log.Printf("Onay sırasında bildirim güncellenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update notification"})
		return // ÖNEMLİ: Hata varsa fonksiyondan çık
	}

	// Her şey yolundaysa transaction'ı onayla.
	if err := tx.Commit(context.Background()); err != nil {
		log.Printf("Admin onay tx commit edilemedi: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during approval"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Payment notification approved and user balance updated."})
}

// GrantAdminHandler, belirtilen kullanıcıya 'admin' rolü atar.
// Sadece Master Admin tarafından erişilebilir olmalıdır.
func (h *Handler) GrantAdminHandler(c *gin.Context) {
	// Rolü atanacak kullanıcının ID'sini URL'den alıyoruz (örn: /master-admin/users/USER_ID/grant-admin)
	userIDToGrant, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	sql := `UPDATE users SET role = 'admin' WHERE id = $1`

	result, err := h.DB.Exec(context.Background(), sql, userIDToGrant)
	if err != nil {
		log.Printf("Admin yetkisi verilirken veritabanı hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update user role"})
		return
	}

	// UPDATE sorgusunun gerçekten bir satırı etkileyip etkilemediğini kontrol ediyoruz.
	// Eğer 0 ise, o ID'ye sahip bir kullanıcı bulunamamıştır.
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User has been granted admin role successfully"})
}

// internal/handlers/handlers.go dosyasına eklenecek

// GrantApproverHandler, belirtilen kullanıcıya 'approver' rolü atar.
// Admin veya Master Admin tarafından erişilebilir olmalıdır.
func (h *Handler) GrantApproverHandler(c *gin.Context) {
	userIDToGrant, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	sql := `UPDATE users SET role = 'approver' WHERE id = $1`

	result, err := h.DB.Exec(context.Background(), sql, userIDToGrant)
	if err != nil {
		log.Printf("Onaylayıcı yetkisi verilirken veritabanı hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update user role"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User has been granted approver role successfully"})
}

func (h *Handler) ChangePasswordHandler(c *gin.Context) {
	// 1. Context'ten kullanıcı ID'sini al.
	userIDString, _ := c.Get("userID")
	userID, _ := uuid.Parse(userIDString.(string))

	// 2. İstekten gelen JSON verisini al ve doğrula.
	var requestBody struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 3. Veritabanından kullanıcının mevcut şifre hash'ini çek.
	var currentPasswordHash string
	sql := `SELECT password_hash FROM users WHERE id = $1`
	err := h.DB.QueryRow(context.Background(), sql, userID).Scan(&currentPasswordHash)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// 4. Mevcut şifrenin doğruluğunu kontrol et.
	err = bcrypt.CompareHashAndPassword([]byte(currentPasswordHash), []byte(requestBody.CurrentPassword))
	if err != nil {
		// Şifre yanlışsa, bcrypt bir hata döndürür.
		// Güvenlik için "Mevcut şifre yanlış" gibi spesifik bir mesaj vermiyoruz.
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid current password"})
		return
	}

	// 5. Yeni şifreyi hash'le.
	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(requestBody.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash new password"})
		return
	}

	// 6. Veritabanında yeni şifre hash'ini güncelle.
	updateSQL := `UPDATE users SET password_hash = $1 WHERE id = $2`
	_, err = h.DB.Exec(context.Background(), updateSQL, string(newHashedPassword), userID)
	if err != nil {
		log.Printf("Şifre güncellenirken veritabanı hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}

func (h *Handler) ListPaymentNotificationsHandler(c *gin.Context) {
	// Query parametresi olarak bir status alıyoruz, eğer belirtilmezse varsayılan olarak 'pending' kullanılıyor.
	// Bu sayede adminler ?status=approved gibi filtrelemeler de yapabilir.
	status := c.DefaultQuery("status", "pending")

	// Admin paneli için kullanıcı adını da göstermek faydalı olacağından, users tablosuyla JOIN yapıyoruz.
	sql := `
		SELECT pn.id, pn.user_id, u.username, pn.amount, pn.status, pn.notes, pn.created_at
		FROM payment_notifications pn
		JOIN users u ON pn.user_id = u.id
		WHERE pn.status = $1 
		ORDER BY pn.created_at ASC` // En eski bildirim en üstte olacak şekilde sıralıyoruz.

	rows, err := h.DB.Query(context.Background(), sql, status)
	if err != nil {
		log.Printf("Ödeme bildirimleri listelenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch payment notifications"})
		return
	}
	defer rows.Close()

	// Sonuçları tutmak için geçici bir struct listesi oluşturuyoruz.
	// Bu struct, models.PaymentNotification'a ek olarak username içeriyor.
	notifications := make([]struct {
		ID        uuid.UUID `json:"id"`
		UserID    uuid.UUID `json:"user_id"`
		Username  string    `json:"username"`
		Amount    float64   `json:"amount"`
		Status    string    `json:"status"`
		Notes     *string   `json:"notes,omitempty"`
		CreatedAt time.Time `json:"created_at"`
	}, 0)

	for rows.Next() {
		var notif struct {
			ID        uuid.UUID `json:"id"`
			UserID    uuid.UUID `json:"user_id"`
			Username  string    `json:"username"`
			Amount    float64   `json:"amount"`
			Status    string    `json:"status"`
			Notes     *string   `json:"notes,omitempty"`
			CreatedAt time.Time `json:"created_at"`
		}
		if err := rows.Scan(&notif.ID, &notif.UserID, &notif.Username, &notif.Amount, &notif.Status, &notif.Notes, &notif.CreatedAt); err != nil {
			log.Printf("Bildirim satırı okunurken hata: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error processing notification data"})
			return
		}
		notifications = append(notifications, notif)
	}

	if err := rows.Err(); err != nil {
		log.Printf("Bildirimler okunurken satır hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reading notification list"})
		return
	}

	c.JSON(http.StatusOK, notifications)
}

// RejectPaymentNotificationHandler, bir adminin ödeme bildirimini reddetmesini sağlar.
func (h *Handler) RejectPaymentNotificationHandler(c *gin.Context) {
	// DİKKAT: Gerçek bir uygulamada, bu endpoint'i çağıran kişinin admin rolüne
	// sahip olup olmadığını kontrol eden bir middleware olmalıdır.

	// Onaylayan adminin ID'sini context'ten alıyoruz, böylece kimin reddettiğini kaydedebiliriz.
	// Bu rota admin grubunda olmadığı için şimdilik bu bilgiyi alamayız,
	// ama admin middleware'i eklendiğinde bu satır çalışacaktır.
	// adminID, _ := c.Get("userID")

	notificationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid notification ID format"})
		return
	}

	// Sadece 'pending' durumundaki bildirimlerin reddedilebildiğinden emin oluyoruz.
	sql := `
		UPDATE payment_notifications 
		SET status = 'rejected', reviewed_at = NOW() --, reviewed_by = $1
		WHERE id = $2 AND status = 'pending'`

	result, err := h.DB.Exec(context.Background(), sql, notificationID) // adminID'yi de ekleyebiliriz
	if err != nil {
		log.Printf("Bildirim reddedilirken veritabanı hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update notification status"})
		return
	}

	// Eğer etkilenen satır sayısı 0 ise, ya bildirim bulunamamıştır ya da 'pending' durumunda değildir.
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Pending notification not found or already processed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Payment notification has been rejected."})
}

func (h *Handler) UpdateUserBankInfoHandler(c *gin.Context) {
	ctx := c.Request.Context() // Context güncellendi
	userIDString, _ := c.Get("userID")
	userID, _ := uuid.Parse(userIDString.(string))

	var requestBody struct {
		IBAN               *string `json:"iban"`                 // Artık pointer
		WithdrawalBankName *string `json:"withdrawal_bank_name"` // YENİ EKLENDİ - Pointer
	}
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// IBAN için temizleme ve format kontrolü (önceki adımdaki gibi, isteğe bağlı)
	var finalIBAN *string
	if requestBody.IBAN != nil && *requestBody.IBAN != "" {
		tempIBAN := strings.ReplaceAll(*requestBody.IBAN, " ", "")
		tempIBAN = strings.ToUpper(tempIBAN)
		finalIBAN = &tempIBAN
	} else {
		finalIBAN = nil // IBAN boş gönderildiyse null yap
	}

	// Banka adı boş gönderildiyse null yap
	var finalBankName *string
	if requestBody.WithdrawalBankName != nil && *requestBody.WithdrawalBankName != "" {
		finalBankName = requestBody.WithdrawalBankName
	} else {
		finalBankName = nil
	}

	// Hem IBAN hem Banka Adı'nı güncelle
	sql := `UPDATE users SET iban = $1, withdrawal_bank_name = $2 WHERE id = $3`
	_, err := h.DB.Exec(ctx, sql, finalIBAN, finalBankName, userID) // Context güncellendi
	if err != nil {
		log.Printf("Banka bilgisi güncellenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update bank information"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Bank information updated successfully."})
}

func (h *Handler) CreateWithdrawalRequestHandler(c *gin.Context) {
	userIDString, _ := c.Get("userID")
	userID, _ := uuid.Parse(userIDString.(string))

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
		log.Printf("Withdrawal tx başlatılamadı: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer tx.Rollback(context.Background())

	// Adım 1: Kullanıcının bakiyesini ve IBAN'ını kontrol et.
	// Cüzdan satırını FOR UPDATE ile kilitleyerek, bu işlem sırasında kullanıcının
	// başka bir harcama yapıp bakiyeyi değiştirmesini engelliyoruz.
	var balance float64
	var iban *string // IBAN null olabilir, bu yüzden pointer kullanıyoruz.
	selectSQL := `
		SELECT w.balance, u.iban 
		FROM wallets w JOIN users u ON w.user_id = u.id 
		WHERE u.id = $1 FOR UPDATE`

	err = tx.QueryRow(context.Background(), selectSQL, userID).Scan(&balance, &iban)
	if err != nil {
		log.Printf("Para çekme talebinde kullanıcı bilgileri alınamadı: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not retrieve user wallet information"})
		return
	}

	// Adım 2: İş kurallarını kontrol et.
	if iban == nil || *iban == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Please add your bank information (IBAN) to your profile before requesting a withdrawal."})
		return
	}
	if balance < requestBody.Amount {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Insufficient funds"})
		return
	}

	// Adım 3: Para çekme talebini veritabanına ekle.
	// DİKKAT: Bu adımda kullanıcının bakiyesini HENÜZ DÜŞÜRMÜYORUZ.
	insertSQL := `
		INSERT INTO withdrawal_requests (user_id, amount, target_iban) 
		VALUES ($1, $2, $3)`
	_, err = tx.Exec(context.Background(), insertSQL, userID, requestBody.Amount, *iban)
	if err != nil {
		log.Printf("Para çekme talebi oluşturulurken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create withdrawal request"})
		return
	}

	// --- TRANSACTION'I ONAYLA ---
	if err := tx.Commit(context.Background()); err != nil {
		log.Printf("Withdrawal tx commit edilemedi: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Withdrawal request created successfully. It will be reviewed by an administrator."})
}

func (h *Handler) ListWithdrawalRequestsHandler(c *gin.Context) {
	ctx := c.Request.Context() // Context güncellendi
	status := c.DefaultQuery("status", "pending")

	// Users tablosuyla JOIN yaparak kullanıcı adı ve banka adını alalım
	sql := `
		SELECT
			wr.id, wr.user_id, u.username, wr.amount, wr.target_iban, wr.status, wr.created_at,
			u.withdrawal_bank_name 
			wr.reviewed_by, wr.reviewed_at
		FROM withdrawal_requests wr
		JOIN users u ON wr.user_id = u.id
		WHERE wr.status = $1
		ORDER BY wr.created_at ASC`

	rows, err := h.DB.Query(ctx, sql, status) // Context güncellendi
	if err != nil {
		log.Printf("Para çekme talepleri listelenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch withdrawal requests"})
		return
	}
	defer rows.Close()

	// Güncellenmiş models.WithdrawalRequest struct'ına okuyalım
	requests, err := pgx.CollectRows(rows, pgx.RowToStructByName[models.WithdrawalRequest])
	if err != nil {
		log.Printf("Çekme talebi satırları işlenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error processing request data"})
		return
	}

	c.JSON(http.StatusOK, requests)
}

// ApproveWithdrawalRequestHandler, bir adminin para çekme talebini onaylamasını sağlar.
func (h *Handler) ApproveWithdrawalRequestHandler(c *gin.Context) {
	// DİKKAT: Bu endpoint admin yetkisi ile korunmalıdır.
	// adminID, _ := c.Get("userID") // Admin middleware'i eklenince kullanılacak.

	requestID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request ID format"})
		return
	}

	tx, err := h.DB.Begin(context.Background())
	if err != nil { /* ...hata kontrolü... */
	}
	defer tx.Rollback(context.Background())

	// Adım 1: Talebi al, 'pending' olduğundan emin ol ve kilitle.
	var request models.WithdrawalRequest
	err = tx.QueryRow(context.Background(), `SELECT id, user_id, amount, status FROM withdrawal_requests WHERE id = $1 FOR UPDATE`, requestID).Scan(&request.ID, &request.UserID, &request.Amount, &request.Status)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Withdrawal request not found"})
		return
	}
	if request.Status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "This request has already been processed."})
		return
	}

	// Adım 2: Kullanıcının bakiyesini düşür.
	// Bu bir güvenlik kontrolüdür, bakiye zaten talep oluşturulurken kontrol edilmişti.
	result, err := tx.Exec(context.Background(), `UPDATE wallets SET balance = balance - $1 WHERE user_id = $2 AND balance >= $1`, request.Amount, request.UserID)
	if err != nil { /* ...hata kontrolü... */
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Insufficient funds or wallet not found."})
		return
	}

	// Adım 3: İşlem kaydını (transaction log) oluştur.
	var walletID uuid.UUID
	tx.QueryRow(context.Background(), `SELECT id FROM wallets WHERE user_id = $1`, request.UserID).Scan(&walletID)
	_, err = tx.Exec(context.Background(), `INSERT INTO transactions (wallet_id, type, amount, status) VALUES ($1, 'withdrawal', $2, 'completed')`, walletID, -request.Amount)
	if err != nil { /* ...hata kontrolü... */
	}

	// Adım 4: Para çekme talebinin durumunu 'completed' olarak güncelle.
	_, err = tx.Exec(context.Background(), `UPDATE withdrawal_requests SET status = 'completed', reviewed_at = NOW() WHERE id = $1`, requestID)
	if err != nil { /* ...hata kontrolü... */
	}

	// Her şey yolundaysa transaction'ı onayla.
	if err := tx.Commit(context.Background()); err != nil {
		log.Printf("Para çekme onayı tx commit edilemedi: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during approval"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Withdrawal request approved and user balance updated."})
}

func (h *Handler) RejectWithdrawalRequestHandler(c *gin.Context) {
	requestID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request ID format"})
		return
	}

	// Sadece 'pending' durumundaki taleplerin reddedilebildiğinden emin oluyoruz.
	// Kullanıcının bakiyesinde bir değişiklik yapılmaz.
	sql := `
		UPDATE withdrawal_requests 
		SET status = 'rejected', reviewed_at = NOW()
		WHERE id = $1 AND status = 'pending'`

	result, err := h.DB.Exec(context.Background(), sql, requestID)
	if err != nil {
		log.Printf("Para çekme talebi reddedilirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update request status"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Pending withdrawal request not found or already processed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Withdrawal request has been rejected."})
}

func (h *Handler) GetListingByIDHandler(c *gin.Context) {
	// URL'den 'id' parametresini alıyoruz (örn: /listings/abc-123)
	listingID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid listing ID format"})
		return
	}

	sql := `SELECT id, seller_id, item_name, description, price, status, created_at 
			FROM listings 
			WHERE id = $1`

	var listing models.Listing
	// QueryRow kullanarak tek bir satır çekiyoruz.
	err = h.DB.QueryRow(context.Background(), sql, listingID).Scan(
		&listing.ID, &listing.SellerID, &listing.ItemName, &listing.Description, &listing.Price, &listing.Status, &listing.CreatedAt,
	)

	if err != nil {
		// Eğer pgx.ErrNoRows hatası dönerse, bu ID'ye sahip bir ilan yoktur.
		if err.Error() == "no rows in result set" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Listing not found"})
			return
		}
		log.Printf("İlan getirilirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch listing"})
		return
	}

	c.JSON(http.StatusOK, listing)
}

func (h *Handler) ListUsersHandler(c *gin.Context) {
	usernameQuery := c.Query("username")

	sql := `
		SELECT u.id, u.username, u.email, u.role, u.account_status, w.balance, u.created_at
		FROM users u 
		LEFT JOIN wallets w ON u.id = w.user_id`

	// Argümanları tutmak için standart bir Go slice'ı kullanıyoruz.
	var args []any

	if usernameQuery != "" {
		sql += " WHERE u.username ILIKE $1"
		args = append(args, "%"+usernameQuery+"%")
	}
	sql += " ORDER BY u.created_at DESC"

	// Sorguyu çalıştırırken, slice'ı 'args...' şeklinde "açarak" gönderiyoruz.
	rows, err := h.DB.Query(context.Background(), sql, args...)
	if err != nil {
		log.Printf("Kullanıcılar listelenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch users"})
		return
	}
	defer rows.Close()

	type UserDetail struct {
		ID            uuid.UUID `json:"id"`
		Username      string    `json:"username"`
		Email         string    `json:"email"`
		Role          string    `json:"role"`
		AccountStatus string    `json:"account_status"`
		Balance       float64   `json:"balance"`
		CreatedAt     time.Time `json:"created_at"`
	}

	users := make([]UserDetail, 0)
	for rows.Next() {
		var user UserDetail
		// Not: Scan içerisindeki AccountStatus alanını eklediğinizden emin olun.
		if err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.AccountStatus, &user.Balance, &user.CreatedAt); err != nil {
			log.Printf("Kullanıcı satırı okunurken hata: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error processing user data"})
			return
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		log.Printf("Kullanıcı listesi okunurken satır hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reading user list"})
		return
	}

	c.JSON(http.StatusOK, users)
}

// UpdateUserRoleHandler, bir adminin başka bir kullanıcının rolünü değiştirmesini sağlar.
func (h *Handler) UpdateUserRoleHandler(c *gin.Context) {
	// İşlemi yapan adminin ID ve Rol'ünü JWT'den alıyoruz.
	actorIDString, _ := c.Get("userID")
	actorRole, _ := c.Get("userRole")

	// actorIDString'i bu fonksiyonda doğrudan kullanmıyoruz ama actorRole'ü alıyoruz.
	// Bu satırları eklemek hatayı çözecektir.
	_ = actorIDString // Bu satır 'actorIDString declared and not used' hatasını engeller.

	// Rolü değiştirilecek kullanıcının ID'sini URL'den al.
	targetUserID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	// İstek body'sinden yeni rolü al.
	var requestBody struct {
		Role string `json:"role" binding:"required"`
	}
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	newRole := requestBody.Role

	// Güvenlik Kontrolleri
	if newRole == "master_admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot assign master_admin role."})
		return
	}

	var targetCurrentRole string
	err = h.DB.QueryRow(context.Background(), `SELECT role FROM users WHERE id = $1`, targetUserID).Scan(&targetCurrentRole)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Target user not found."})
		return
	}

	if targetCurrentRole == "master_admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot change the role of a master_admin."})
		return
	}

	if actorRole == "admin" {
		if newRole == "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Admins cannot create other admins."})
			return
		}
		if targetCurrentRole == "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Admins cannot modify other admins."})
			return
		}
	}

	// Tüm kontrollerden geçtiyse, rolü güncelle.
	sql := `UPDATE users SET role = $1 WHERE id = $2`
	_, err = h.DB.Exec(context.Background(), sql, newRole, targetUserID)
	if err != nil {
		log.Printf("Kullanıcı rolü güncellenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update user role"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User role updated successfully."})
}

// internal/handlers/handlers.go dosyasına eklenecek

func (h *Handler) BanUserHandler(c *gin.Context) {
	userIDToBan, _ := uuid.Parse(c.Param("id"))

	// Güvenlik: Kimsenin master_admin'i banlayamadığından emin ol
	var role string
	h.DB.QueryRow(context.Background(), `SELECT role FROM users WHERE id=$1`, userIDToBan).Scan(&role)
	if role == "master_admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Master admin cannot be banned."})
		return
	}

	_, err := h.DB.Exec(context.Background(), `UPDATE users SET account_status = 'banned' WHERE id = $1`, userIDToBan)
	if err != nil { /* ...hata kontrolü... */
	}
	c.JSON(http.StatusOK, gin.H{"message": "User has been banned."})
}

func (h *Handler) UnbanUserHandler(c *gin.Context) {
	userIDToUnban, _ := uuid.Parse(c.Param("id"))
	_, err := h.DB.Exec(context.Background(), `UPDATE users SET account_status = 'active' WHERE id = $1`, userIDToUnban)
	if err != nil { /* ...hata kontrolü... */
	}
	c.JSON(http.StatusOK, gin.H{"message": "User has been unbanned."})
}

func (h *Handler) ListPrivilegedUsersHandler(c *gin.Context) {
	sql := `
		SELECT id, username, email, role
		FROM users 
		WHERE role = 'admin' OR role = 'approver'
		ORDER BY role, username`

	rows, err := h.DB.Query(context.Background(), sql)
	if err != nil {
		log.Printf("Yetkili kullanıcılar listelenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch privileged users"})
		return
	}
	defer rows.Close()

	// Bu sefer daha az bilgiye ihtiyacımız olduğu için basit bir struct kullanabiliriz.
	users := make([]struct {
		ID       uuid.UUID `json:"id"`
		Username string    `json:"username"`
		Email    string    `json:"email"`
		Role     string    `json:"role"`
	}, 0)

	for rows.Next() {
		var user struct {
			ID       uuid.UUID `json:"id"`
			Username string    `json:"username"`
			Email    string    `json:"email"`
			Role     string    `json:"role"`
		}
		if err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.Role); err != nil {
			log.Printf("Yetkili kullanıcı satırı okunurken hata: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error processing user data"})
			return
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil { /* ...hata kontrolü... */
	}

	c.JSON(http.StatusOK, users)
}

// internal/handlers/handlers.go

// ListManageableUsersHandler, giriş yapan adminin rolüne göre yönetebileceği kullanıcıları listeler.
func (h *Handler) ListManageableUsersHandler(c *gin.Context) {
	actorRole, _ := c.Get("userRole")

	var sql string
	if actorRole == "master_admin" {
		sql = `SELECT id, username, email, role FROM users WHERE role = 'admin' OR role = 'approver' ORDER BY role, username`
	} else if actorRole == "admin" {
		sql = `SELECT id, username, email, role FROM users WHERE role = 'approver' ORDER BY username`
	} else {
		// Approver veya daha altı bir rol buraya gelirse boş liste dönsün.
		c.JSON(http.StatusOK, []interface{}{})
		return
	}

	rows, err := h.DB.Query(context.Background(), sql)
	if err != nil {
		log.Printf("Yönetilebilir kullanıcılar listelenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch users"})
		return
	}
	defer rows.Close()
	users := make([]struct {
		ID       uuid.UUID `json:"id"`
		Username string    `json:"username"`
		Email    string    `json:"email"`
		Role     string    `json:"role"`
	}, 0)

	for rows.Next() {
		var user struct {
			ID       uuid.UUID `json:"id"`
			Username string    `json:"username"`
			Email    string    `json:"email"`
			Role     string    `json:"role"`
		}
		if err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.Role); err != nil {
			log.Printf("Yetkili kullanıcı satırı okunurken hata: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error processing user data"})
			return
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil { /* ...hata kontrolü... */
	}

	c.JSON(http.StatusOK, users)
}

func (h *Handler) ListDepositBanksHandler(c *gin.Context) {
	ctx := c.Request.Context()
	sql := `SELECT id, bank_name, iban, account_holder_name, is_active, created_at, updated_at
			FROM deposit_banks ORDER BY bank_name ASC`

	rows, err := h.DB.Query(ctx, sql)
	if err != nil {
		log.Printf("Banka listesi alınırken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch deposit banks"})
		return
	}
	defer rows.Close()

	banks, err := pgx.CollectRows(rows, pgx.RowToStructByName[models.DepositBank])
	if err != nil {
		log.Printf("Banka listesi işlenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error processing bank data"})
		return
	}

	c.JSON(http.StatusOK, banks)
}

func (h *Handler) GetActiveDepositBanksHandler(c *gin.Context) {
	ctx := c.Request.Context()
	// Sadece ID, Banka Adı ve IBAN yeterli olabilir kullanıcı için
	sql := `SELECT id, bank_name, iban, account_holder_name
			FROM deposit_banks WHERE is_active = true ORDER BY bank_name ASC`

	rows, err := h.DB.Query(ctx, sql)
	if err != nil {
		log.Printf("Aktif banka listesi alınırken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch active deposit banks"})
		return
	}
	defer rows.Close()

	// Sadece gerekli alanları içeren geçici bir struct kullanalım
	type ActiveBankInfo struct {
		ID                uuid.UUID `json:"id"`
		BankName          string    `json:"bank_name"`
		IBAN              *string   `json:"iban"` // Gösterilecek IBAN
		AccountHolderName *string   `json:"account_holder_name"`
	}

	banks, err := pgx.CollectRows(rows, pgx.RowToStructByName[ActiveBankInfo])
	if err != nil {
		log.Printf("Aktif banka listesi işlenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error processing active bank data"})
		return
	}

	c.JSON(http.StatusOK, banks)
}

func (h *Handler) UpdateDepositBankHandler(c *gin.Context) {
	ctx := c.Request.Context()
	bankID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid bank ID format"})
		return
	}

	var requestBody struct {
		IBAN              *string `json:"iban"` // Pointer, boş gönderilebilmesi için
		AccountHolderName *string `json:"account_holder_name"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// --- IBAN Regex Kontrolü Kaldırıldı ---
	// Gelen IBAN'ın boşluklarını temizle ve büyük harfe çevir (isteğe bağlı, formatı korumak için kalabilir)
	var finalIBAN *string
	if requestBody.IBAN != nil && *requestBody.IBAN != "" {
		tempIBAN := strings.ReplaceAll(*requestBody.IBAN, " ", "")
		tempIBAN = strings.ToUpper(tempIBAN)
		finalIBAN = &tempIBAN
	} else {
		// Eğer IBAN boş gönderildiyse veya null ise, null olarak kaydet
		finalIBAN = nil
	}
	// --- Kontrol Sonu ---

	// Temizlenmiş (veya null) IBAN'ı veritabanına kaydet
	sql := `UPDATE deposit_banks SET iban = $1, account_holder_name = $2, updated_at = NOW() WHERE id = $3`
	_, err = h.DB.Exec(ctx, sql, finalIBAN, requestBody.AccountHolderName, bankID) // finalIBAN kullanıldı
	if err != nil {
		log.Printf("Banka bilgisi güncellenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update bank information"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Bank information updated successfully."})
}

func (h *Handler) ToggleDepositBankStatusHandler(c *gin.Context) {
	ctx := c.Request.Context()
	bankID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid bank ID format"})
		return
	}

	// Mevcut durumu alıp tersine çevirelim
	var currentStatus bool
	err = h.DB.QueryRow(ctx, "SELECT is_active FROM deposit_banks WHERE id = $1", bankID).Scan(&currentStatus)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Bank not found"})
		return
	}

	newStatus := !currentStatus
	sql := `UPDATE deposit_banks SET is_active = $1, updated_at = NOW() WHERE id = $2`
	_, err = h.DB.Exec(ctx, sql, newStatus, bankID)
	if err != nil {
		log.Printf("Banka durumu güncellenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update bank status"})
		return
	}

	message := "Bank activated successfully."
	if !newStatus {
		message = "Bank deactivated successfully."
	}
	c.JSON(http.StatusOK, gin.H{"message": message, "new_status": newStatus})
}
