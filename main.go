package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type DailyCalorieLimit struct {
	gorm.Model      `json:"-"`
	UserID          string  `json:"user_id" gorm:"not null"`
	Date            string  `json:"date"`
	BaseCalories    float64 `json:"base_calories"`
	WorkoutCalories float64 `json:"workout_calories"`
}

type NutritionEntry struct {
	gorm.Model  `json:"-"`
	UserID      string  `json:"user_id" gorm:"not null"`
	Date        string  `json:"date"`
	Food        string  `json:"food"`
	Calories    float64 `json:"calories"`
	Protein     float64 `json:"protein"`
	Carbs       float64 `json:"carbs"`
	Fat         float64 `json:"fat"`
	Description string  `json:"description"`
}

type CalorieCalculation struct {
	Date              string           `json:"date"`
	BaseCalories      float64          `json:"base_calories"`
	WorkoutCalories   float64          `json:"workout_calories"`
	ConsumedCalories  float64          `json:"consumed_calories"`
	RemainingCalories float64          `json:"remaining_calories"`
	Entries           []NutritionEntry `json:"entries"`
}

type Weight struct {
	gorm.Model `json:"-"`
	UserID     string  `json:"user_id" gorm:"not null"`
	Date       string  `json:"date" gorm:"not null"`
	Weight     float64 `json:"weight" gorm:"not null"`
	Notes      string  `json:"notes"`
}

type OAuth2Config struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	AuthURL      string
	TokenURL     string
	Scopes       []string
}

var (
	db            *gorm.DB
	oauth2Config  OAuth2Config
	jwksCache     = make(map[string]*rsa.PublicKey)
	jwksCacheMu   sync.RWMutex
	jwksCacheTime time.Time
	publicKeys    = make(map[string]*rsa.PublicKey)
)

func createDailyLimit(c *gin.Context) {
	var limit DailyCalorieLimit
	if err := c.ShouldBindJSON(&limit); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	userID, _ := c.Get("userID")
	limit.UserID = userID.(string)

	// Check if a limit already exists for this date and user
	var existingLimit DailyCalorieLimit
	if result := db.Where("user_id = ? AND date = ?", limit.UserID, limit.Date).First(&existingLimit); result.Error == nil {
		// Update existing limit
		existingLimit.BaseCalories = limit.BaseCalories
		existingLimit.WorkoutCalories = limit.WorkoutCalories
		db.Save(&existingLimit)
		c.JSON(200, existingLimit)
		return
	}

	// Create new limit
	db.Create(&limit)
	c.JSON(201, limit)
}

func getDailyLimit(c *gin.Context) {
	date := c.Param("date")
	userID, _ := c.Get("userID")
	var limit DailyCalorieLimit

	if err := db.Where("user_id = ? AND date = ?", userID, date).First(&limit).Error; err != nil {
		// Return a default limit if none exists
		limit = DailyCalorieLimit{
			UserID:          userID.(string),
			Date:            date,
			BaseCalories:    2000, // Default daily calorie limit
			WorkoutCalories: 0,
		}
	}

	c.JSON(200, limit)
}

func createEntry(c *gin.Context) {
	var entry NutritionEntry
	if err := c.ShouldBindJSON(&entry); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	userID, _ := c.Get("userID")
	entry.UserID = userID.(string)

	db.Create(&entry)
	c.JSON(201, entry)
}

func getEntries(c *gin.Context) {
	userID, _ := c.Get("userID")
	var entries []NutritionEntry
	if err := db.Where("user_id = ?", userID).Find(&entries).Error; err != nil {
		entries = []NutritionEntry{} // Return empty array if error
	}
	c.JSON(200, entries)
}

func getEntry(c *gin.Context) {
	id := c.Param("id")
	userID, _ := c.Get("userID")
	var entry NutritionEntry

	if err := db.Where("user_id = ?", userID).First(&entry, id).Error; err != nil {
		if err.Error() == "record not found" {
			c.JSON(404, gin.H{"error": "Entry not found"})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, entry)
}

func getEntriesByDate(c *gin.Context) {
	date := c.Param("date")
	userID, _ := c.Get("userID")
	var entries []NutritionEntry

	db.Where("user_id = ? AND date = ?", userID, date).Find(&entries)
	c.JSON(200, entries)
}

func getDailyCalories(c *gin.Context) {
	date := c.Param("date")
	userID, _ := c.Get("userID")

	// Get daily limit
	var limit DailyCalorieLimit
	if err := db.Where("user_id = ? AND date = ?", userID, date).First(&limit).Error; err != nil {
		c.JSON(404, gin.H{"error": "Daily limit not found for this date"})
		return
	}

	// Get all entries for the date
	var entries []NutritionEntry
	db.Where("user_id = ? AND date = ?", userID, date).Find(&entries)

	// Calculate total consumed calories
	var consumedCalories float64
	for _, entry := range entries {
		consumedCalories += entry.Calories
	}

	// Calculate remaining calories
	remainingCalories := limit.BaseCalories + limit.WorkoutCalories - consumedCalories

	calculation := CalorieCalculation{
		Date:              date,
		BaseCalories:      limit.BaseCalories,
		WorkoutCalories:   limit.WorkoutCalories,
		ConsumedCalories:  consumedCalories,
		RemainingCalories: remainingCalories,
		Entries:           entries,
	}

	c.JSON(200, calculation)
}

func updateEntry(c *gin.Context) {
	id := c.Param("id")
	userID, _ := c.Get("userID")
	var entry NutritionEntry

	if err := db.Where("user_id = ?", userID).First(&entry, id).Error; err != nil {
		if err.Error() == "record not found" {
			c.JSON(404, gin.H{"error": "Entry not found"})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Only allow updating the entry if it belongs to the user
	if entry.UserID != userID.(string) {
		c.JSON(403, gin.H{"error": "Not authorized to update this entry"})
		return
	}

	if err := c.ShouldBindJSON(&entry); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	entry.UserID = userID.(string) // Ensure UserID remains unchanged
	db.Save(&entry)
	c.JSON(200, entry)
}

func deleteEntry(c *gin.Context) {
	id := c.Param("id")
	userID, _ := c.Get("userID")
	var entry NutritionEntry

	if err := db.Where("user_id = ?", userID).First(&entry, id).Error; err != nil {
		if err.Error() == "record not found" {
			c.JSON(404, gin.H{"error": "Entry not found"})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Only allow deleting the entry if it belongs to the user
	if entry.UserID != userID.(string) {
		c.JSON(403, gin.H{"error": "Not authorized to delete this entry"})
		return
	}

	db.Delete(&entry)
	c.JSON(200, gin.H{"message": "Entry deleted successfully"})
}

func createWeight(c *gin.Context) {
	var weight Weight
	if err := c.ShouldBindJSON(&weight); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	userID, _ := c.Get("userID")
	weight.UserID = userID.(string)

	if err := db.Create(&weight).Error; err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(201, weight)
}

func getWeight(c *gin.Context) {
	id := c.Param("id")
	userID, _ := c.Get("userID")
	var weight Weight

	if err := db.Where("user_id = ?", userID).First(&weight, id).Error; err != nil {
		if err.Error() == "record not found" {
			c.JSON(404, gin.H{"error": "Weight record not found"})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, weight)
}

func getWeightsByDate(c *gin.Context) {
	date := c.Param("date")
	userID, _ := c.Get("userID")
	var weights []Weight

	if err := db.Where("user_id = ? AND date = ?", userID, date).Find(&weights).Error; err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, weights)
}

func getWeights(c *gin.Context) {
	userID, _ := c.Get("userID")
	var weights []Weight
	if err := db.Where("user_id = ?", userID).Find(&weights).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving weights"})
		return
	}
	c.JSON(http.StatusOK, weights)
}

func updateWeight(c *gin.Context) {
	id := c.Param("id")
	userID, _ := c.Get("userID")
	var weight Weight

	if err := db.Where("user_id = ?", userID).First(&weight, id).Error; err != nil {
		if err.Error() == "record not found" {
			c.JSON(404, gin.H{"error": "Weight record not found"})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Only allow updating the weight if it belongs to the user
	if weight.UserID != userID.(string) {
		c.JSON(403, gin.H{"error": "Not authorized to update this weight"})
		return
	}

	var updatedWeight Weight
	if err := c.ShouldBindJSON(&updatedWeight); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	weight.Date = updatedWeight.Date
	weight.Weight = updatedWeight.Weight
	weight.Notes = updatedWeight.Notes

	if err := db.Save(&weight).Error; err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, weight)
}

func deleteWeight(c *gin.Context) {
	id := c.Param("id")
	userID, _ := c.Get("userID")
	var weight Weight

	if err := db.Where("user_id = ?", userID).First(&weight, id).Error; err != nil {
		if err.Error() == "record not found" {
			c.JSON(404, gin.H{"error": "Weight record not found"})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Only allow deleting the weight if it belongs to the user
	if weight.UserID != userID.(string) {
		c.JSON(403, gin.H{"error": "Not authorized to delete this weight"})
		return
	}

	if err := db.Delete(&weight).Error; err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "Weight record deleted successfully"})
}

type JWTKeys struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func getJWKS() (*JWTKeys, error) {
	resp, err := http.Get("https://dev-lk0vcub54idn0l5c.us.auth0.com/.well-known/jwks.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jwks JWTKeys
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	return &jwks, nil
}

func getPublicKey(token *jwt.Token) (*rsa.PublicKey, error) {
	jwksCacheMu.RLock()
	if publicKey, ok := jwksCache[token.Header["kid"].(string)]; ok {
		if time.Since(jwksCacheTime) < 24*time.Hour {
			jwksCacheMu.RUnlock()
			return publicKey, nil
		}
	}
	jwksCacheMu.RUnlock()

	jwks, err := getJWKS()
	if err != nil {
		return nil, err
	}

	jwksCacheMu.Lock()
	defer jwksCacheMu.Unlock()

	for _, key := range jwks.Keys {
		if key.Kid == token.Header["kid"].(string) {
			// Decode the modulus and exponent
			nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				return nil, err
			}
			eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				return nil, err
			}

			// Convert the modulus bytes to a big integer
			n := new(big.Int)
			n.SetBytes(nBytes)

			// Convert the exponent bytes to an integer
			var eInt int
			for i := 0; i < len(eBytes); i++ {
				eInt = eInt<<8 + int(eBytes[i])
			}

			// Create the public key
			publicKey := &rsa.PublicKey{
				N: n,
				E: eInt,
			}

			// Cache the public key
			jwksCache[key.Kid] = publicKey
			jwksCacheTime = time.Now()

			return publicKey, nil
		}
	}

	return nil, fmt.Errorf("unable to find appropriate key")
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			log.Printf("[Auth] No Authorization header found")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No authorization header"})
			c.Abort()
			return
		}

		// Extract token from Bearer scheme
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			log.Printf("[Auth] Invalid Authorization header format: %s", authHeader)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]
		log.Printf("[Auth] Validating token: %s", tokenString)

		// Parse and validate token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				log.Printf("[Auth] Unexpected signing method: %v", token.Header["alg"])
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// Get key ID from token header
			kid, ok := token.Header["kid"].(string)
			if !ok {
				log.Printf("[Auth] No kid found in token header")
				return nil, fmt.Errorf("no kid found in token header")
			}

			// Get public key for this kid
			key, ok := publicKeys[kid]
			if !ok {
				log.Printf("[Auth] No public key found for kid: %s", kid)
				return nil, fmt.Errorf("no public key found for kid: %s", kid)
			}

			return key, nil
		})

		if err != nil {
			log.Printf("[Auth] Token validation failed: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		if !token.Valid {
			log.Printf("[Auth] Token is invalid")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			log.Printf("[Auth] Failed to extract claims from token")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to extract claims"})
			c.Abort()
			return
		}

		// Log claims for debugging
		log.Printf("[Auth] Token claims: %+v", claims)

		// Store claims in context
		c.Set("user", claims)
		c.Next()
	}
}

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Log headers
		headers := make(map[string]string)
		for k, v := range c.Request.Header {
			if len(v) > 0 {
				// Mask sensitive information
				if k == "Authorization" {
					headers[k] = "Bearer ..."
				} else {
					headers[k] = v[0]
				}
			}
		}
		headerJSON, _ := json.Marshal(headers)
		log.Printf("[GIN] Headers: %s", string(headerJSON))

		// Process request
		c.Next()

		// Stop timer
		end := time.Now()
		latency := end.Sub(start)

		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()
		userID, _ := c.Get("userID")
		if userID == nil {
			userID = "anonymous"
		}

		if raw != "" {
			path = path + "?" + raw
		}

		log.Printf("[GIN] %v | %3d | %13v | %15s | %-7s %s | UserID: %v",
			end.Format("2006/01/02 - 15:04:05"),
			statusCode,
			latency,
			clientIP,
			method,
			path,
			userID,
		)

		// Log errors if any
		if len(c.Errors) > 0 {
			log.Printf("[GIN] Errors: %v", c.Errors.String())
		}
	}
}

func initDB() {
	var err error

	// Get database connection details from environment variables
	dbHost := os.Getenv("DB_HOST")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbPort := os.Getenv("DB_PORT")

	if dbPort == "" {
		dbPort = "5432" // Default PostgreSQL port
	}

	// Construct database connection string with SSL enabled
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=require",
		dbHost, dbUser, dbPassword, dbName, dbPort)

	// Connect to database
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Auto migrate tables (this will create tables if they don't exist)
	err = db.AutoMigrate(&NutritionEntry{}, &DailyCalorieLimit{}, &Weight{})
	if err != nil {
		log.Fatal("Failed to migrate database tables:", err)
	}

	log.Println("Database initialized successfully")
}

func fetchJWKS() error {
	resp, err := http.Get("https://dev-lk0vcub54idn0l5c.us.auth0.com/.well-known/jwks.json")
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %v", err)
	}
	defer resp.Body.Close()

	var jwks struct {
		Keys []struct {
			Kid string   `json:"kid"`
			Kty string   `json:"kty"`
			N   string   `json:"n"`
			E   string   `json:"e"`
			Use string   `json:"use"`
			X5c []string `json:"x5c"`
		} `json:"keys"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %v", err)
	}

	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || key.Use != "sig" {
			continue
		}

		// Decode the public key components
		n, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			log.Printf("[JWKS] Failed to decode key modulus: %v", err)
			continue
		}

		e, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			log.Printf("[JWKS] Failed to decode key exponent: %v", err)
			continue
		}

		// Convert exponent bytes to int
		var eInt int
		for i := 0; i < len(e); i++ {
			eInt = eInt<<8 + int(e[i])
		}

		// Create RSA public key
		publicKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: eInt,
		}

		publicKeys[key.Kid] = publicKey
		log.Printf("[JWKS] Added public key with kid: %s", key.Kid)
	}

	if len(publicKeys) == 0 {
		return fmt.Errorf("no valid RSA keys found in JWKS")
	}

	return nil
}

func initOAuth2Config() {
	// Fetch JWKS on startup
	if err := fetchJWKS(); err != nil {
		log.Printf("[JWKS] Initial JWKS fetch failed: %v", err)
	}

	oauth2Config = OAuth2Config{
		ClientID:     os.Getenv("AUTH0_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTH0_CLIENT_SECRET"),
		RedirectURI:  os.Getenv("AUTH0_REDIRECT_URI"),
		AuthURL:      "https://dev-lk0vcub54idn0l5c.us.auth0.com/authorize",
		TokenURL:     "https://dev-lk0vcub54idn0l5c.us.auth0.com/oauth/token",
		Scopes:       []string{"openid", "profile", "email"},
	}
}

func generateNonce() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func handleOAuth2Authorize(c *gin.Context) {
	// Get parameters from request, falling back to oauth2Config if not provided
	clientID := c.Query("client_id")
	if clientID == "" {
		clientID = oauth2Config.ClientID
	}

	redirectURI := c.Query("redirect_uri")
	if redirectURI == "" {
		redirectURI = oauth2Config.RedirectURI
	}

	scope := c.Query("scope")
	if scope == "" {
		scope = strings.Join(oauth2Config.Scopes, " ")
	}

	// Check if state was provided in request
	state := c.Query("state")
	if state == "" {
		state = uuid.New().String()
		log.Printf("[OAuth2] Generated new state: %s", state)
	} else {
		log.Printf("[OAuth2] Using provided state: %s", state)
	}

	// Generate nonce
	nonce := generateNonce()

	// Store state and nonce in secure cookies
	domain := c.Request.Host
	if strings.Contains(domain, ":") {
		domain = strings.Split(domain, ":")[0]
	}
	if domain == "localhost" {
		domain = ""
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("oauth_state", state, 3600, "/", domain, true, true)
	c.SetCookie("oauth_nonce", nonce, 3600, "/", domain, true, true)

	// Build authorization URL with all necessary parameters
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", "code")
	params.Set("scope", scope)
	params.Set("state", state)
	params.Set("nonce", nonce)

	// Redirect to Auth0
	authURL := oauth2Config.AuthURL + "?" + params.Encode()
	log.Printf("[OAuth2] Redirecting to Auth0 with state: %s", state)

	// Redirect to Auth0 login page
	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

func handleOAuth2Callback(c *gin.Context) {
	// Get state and nonce from cookies
	state, err := c.Cookie("oauth_state")
	if err != nil {
		log.Printf("[OAuth2] Missing state cookie: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing state"})
		return
	}

	nonce, err := c.Cookie("oauth_nonce")
	if err != nil {
		log.Printf("[OAuth2] Missing nonce cookie: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing nonce"})
		return
	}

	// Clear cookies
	domain := c.Request.Host
	if strings.Contains(domain, ":") {
		domain = strings.Split(domain, ":")[0]
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("oauth_state", "", -1, "/", domain, true, true)
	c.SetCookie("oauth_nonce", "", -1, "/", domain, true, true)

	// Verify state
	if c.Query("state") != state {
		log.Printf("[OAuth2] State mismatch")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state"})
		return
	}

	// Exchange code for token with all necessary parameters
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", c.Query("code"))
	data.Set("redirect_uri", oauth2Config.RedirectURI)
	data.Set("client_id", oauth2Config.ClientID)
	data.Set("client_secret", oauth2Config.ClientSecret)
	data.Set("audience", "https://dev-lk0vcub54idn0l5c.us.auth0.com/api/v2/")
	data.Set("scope", "openid profile email offline_access")
	data.Set("response_type", "token id_token")
	data.Set("token_type", "JWT")
	data.Set("nonce", nonce)

	// Create token request
	tokenReq, err := http.NewRequest("POST", oauth2Config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		log.Printf("[OAuth2] Failed to create token request")
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to create token request",
		})
		return
	}

	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send token request
	client := &http.Client{Timeout: 10 * time.Second} // Add timeout
	resp, err := client.Do(tokenReq)
	if err != nil {
		log.Printf("[OAuth2] Token request failed")
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to exchange code for token",
		})
		return
	}
	defer resp.Body.Close()

	// Read response
	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[OAuth2] Failed to read response body")
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to read token response",
		})
		return
	}

	// Log Auth0's raw response
	log.Printf("[OAuth2] Auth0 response status: %d", resp.StatusCode)
	log.Printf("[OAuth2] Auth0 response headers: %+v", resp.Header)
	log.Printf("[OAuth2] Auth0 response body: %s", string(rawBody))

	// Check if Auth0 returned an error
	if resp.StatusCode != http.StatusOK {
		var errorResponse struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.Unmarshal(rawBody, &errorResponse); err != nil {
			c.Header("Content-Type", "application/json")
			c.JSON(resp.StatusCode, gin.H{
				"error":             "server_error",
				"error_description": "Failed to parse error response from Auth0",
			})
			return
		}
		c.Header("Content-Type", "application/json")
		c.JSON(resp.StatusCode, errorResponse)
		return
	}

	// Forward Auth0's response
	c.Header("Content-Type", "application/json")
	c.Data(http.StatusOK, "application/json", rawBody)
}

func handleUserInfo(c *gin.Context) {
	// Get token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid Authorization header"})
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Log token details for debugging
		log.Printf("[UserInfo] Token Headers: %+v", token.Header)

		return getPublicKey(token)
	})

	if err != nil {
		log.Printf("[UserInfo] Token parsing error: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	if !token.Valid {
		log.Printf("[UserInfo] Token is invalid")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Get claims from token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Printf("[UserInfo] Failed to get claims from token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info from token"})
		return
	}

	// Log raw claims for debugging
	log.Printf("[UserInfo] Raw token claims: %+v", claims)

	// Return user info from token claims, with more flexible field access
	response := gin.H{
		"sub":     claims["sub"],
		"email":   getClaimString(claims, "email", ""),
		"name":    getClaimString(claims, "name", ""),
		"picture": getClaimString(claims, "picture", ""),
	}

	// Log the response we're sending back
	log.Printf("[UserInfo] Sending response: %+v", response)

	c.JSON(http.StatusOK, response)
}

func getClaimString(claims jwt.MapClaims, key string, defaultValue string) string {
	if value, exists := claims[key]; exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return defaultValue
}

func generateCodeVerifier() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func handleTokenExchange(c *gin.Context) {
	// Log raw request body
	rawBody, err := io.ReadAll(c.Request.Body)
	if err != nil {
		log.Printf("[OAuth2] Failed to read request body: %v", err)
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Failed to read request body",
		})
		return
	}
	log.Printf("[OAuth2] Token request body: %s", string(rawBody))

	// Parse the form data
	values, err := url.ParseQuery(string(rawBody))
	if err != nil {
		log.Printf("[OAuth2] Failed to parse form data: %v", err)
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid form data",
		})
		return
	}

	// Extract values from form data
	tokenRequest := struct {
		Code         string
		RedirectURI  string
		ClientID     string
		ClientSecret string
		GrantType    string
		Scope        string
	}{
		Code:         values.Get("code"),
		RedirectURI:  values.Get("redirect_uri"),
		ClientID:     values.Get("client_id"),
		ClientSecret: values.Get("client_secret"),
		GrantType:    values.Get("grant_type"),
		Scope:        values.Get("scope"),
	}

	// Validate required fields
	if tokenRequest.Code == "" || tokenRequest.RedirectURI == "" || tokenRequest.GrantType == "" {
		log.Printf("[OAuth2] Missing required fields - code: %v, redirect_uri: %v, grant_type: %v",
			tokenRequest.Code != "", tokenRequest.RedirectURI != "", tokenRequest.GrantType != "")
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing required parameters",
		})
		return
	}

	// Use provided client ID or fall back to config
	clientID := tokenRequest.ClientID
	if clientID == "" {
		clientID = oauth2Config.ClientID
	}

	// Build token request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", tokenRequest.Code)
	data.Set("redirect_uri", tokenRequest.RedirectURI)
	data.Set("client_id", clientID)
	data.Set("client_secret", oauth2Config.ClientSecret)
	data.Set("audience", "https://dev-lk0vcub54idn0l5c.us.auth0.com/api/v2/")
	data.Set("scope", "openid profile email offline_access")
	data.Set("response_type", "token id_token")
	data.Set("token_type", "JWT")

	// Create token request
	tokenReq, err := http.NewRequest("POST", oauth2Config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		log.Printf("[OAuth2] Failed to create token request")
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to create token request",
		})
		return
	}

	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send token request
	client := &http.Client{Timeout: 10 * time.Second} // Add timeout
	resp, err := client.Do(tokenReq)
	if err != nil {
		log.Printf("[OAuth2] Token request failed")
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to exchange code for token",
		})
		return
	}
	defer resp.Body.Close()

	// Read response
	rawBody, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[OAuth2] Failed to read response body")
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to read token response",
		})
		return
	}

	// Log Auth0's raw response
	log.Printf("[OAuth2] Auth0 response status: %d", resp.StatusCode)
	log.Printf("[OAuth2] Auth0 response headers: %+v", resp.Header)
	log.Printf("[OAuth2] Auth0 response body: %s", string(rawBody))

	// Check if Auth0 returned an error
	if resp.StatusCode != http.StatusOK {
		var errorResponse struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.Unmarshal(rawBody, &errorResponse); err != nil {
			c.Header("Content-Type", "application/json")
			c.JSON(resp.StatusCode, gin.H{
				"error":             "server_error",
				"error_description": "Failed to parse error response from Auth0",
			})
			return
		}
		c.Header("Content-Type", "application/json")
		c.JSON(resp.StatusCode, errorResponse)
		return
	}

	// Forward Auth0's response
	c.Header("Content-Type", "application/json")
	c.Data(http.StatusOK, "application/json", rawBody)
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	initOAuth2Config()
	initDB()

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestLogger())

	// Configure CORS
	config := cors.DefaultConfig()
	// Allow requests from both localhost and your GPT integration
	config.AllowOrigins = []string{
		"http://localhost:8080",
		"https://chat.openai.com",
		"https://chat.openai.com/",
		"https://chatgpt.com",
		"https://chatgpt.com/",
		"https://calorie-gpt.onrender.com",
		"https://calorie-gpt.onrender.com/",
	}
	config.AllowCredentials = true
	config.AllowHeaders = []string{
		"Origin",
		"Content-Type",
		"Accept",
		"Authorization",
		"Cookie",
		"Set-Cookie",
	}
	config.ExposeHeaders = []string{
		"Content-Length",
		"Authorization",
		"Set-Cookie",
	}
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	r.Use(cors.New(config))

	// OAuth2 endpoints
	oauth := r.Group("/oauth2")
	{
		oauth.GET("/authorize", handleOAuth2Authorize)
		oauth.GET("/callback", handleOAuth2Callback)
		oauth.POST("/token", handleTokenExchange)
		oauth.GET("/userinfo", handleUserInfo)
	}

	// Static files
	r.Static("/static", "./static")
	r.StaticFile("/", "./static/index.html")
	r.StaticFile("/auth0-config.js", "./static/auth0-config.js")
	r.StaticFile("/app.js", "./static/app.js")

	// Protected API routes
	api := r.Group("/")
	api.Use(authMiddleware())
	{
		api.POST("/daily-limit", createDailyLimit)
		api.GET("/daily-limit/:date", getDailyLimit)
		api.POST("/entries", createEntry)
		api.GET("/entries", getEntries)
		api.GET("/entries/:id", getEntry)
		api.GET("/entries/date/:date", getEntriesByDate)
		api.GET("/calories/:date", getDailyCalories)
		api.PUT("/entries/:id", updateEntry)
		api.DELETE("/entries/:id", deleteEntry)
		api.POST("/weight", createWeight)
		api.GET("/weight", getWeights)
		api.GET("/weight/:id", getWeight)
		api.GET("/weight/date/:date", getWeightsByDate)
		api.PUT("/weight/:id", updateWeight)
		api.DELETE("/weight/:id", deleteWeight)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	r.Run(":" + port)
}
