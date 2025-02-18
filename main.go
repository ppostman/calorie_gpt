package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"sync"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

type DailyCalorieLimit struct {
	gorm.Model      `json:"-"`
	UserID          string  `json:"user_id" gorm:"not null"`
	Date            string  `json:"date"`
	BaseCalories    float64 `json:"base_calories"`
	WorkoutCalories float64 `json:"workout_calories"`
}

type NutritionEntry struct {
	gorm.Model   `json:"-"`
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
	Date               string  `json:"date"`
	BaseCalories      float64 `json:"base_calories"`
	WorkoutCalories   float64 `json:"workout_calories"`
	ConsumedCalories  float64 `json:"consumed_calories"`
	RemainingCalories float64 `json:"remaining_calories"`
	Entries           []NutritionEntry `json:"entries"`
}

type Weight struct {
	gorm.Model `json:"-"`
	UserID string  `json:"user_id" gorm:"not null"`
	Date   string  `json:"date" gorm:"not null"`
	Weight float64 `json:"weight" gorm:"not null"`
	Notes  string  `json:"notes"`
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
	db *gorm.DB
	oauth2Config OAuth2Config
	jwksCache     = make(map[string]*rsa.PublicKey)
	jwksCacheMu   sync.RWMutex
	jwksCacheTime time.Time
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
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(401, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		// Extract bearer token
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(401, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := authHeader[7:]
		if tokenString == "" {
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Parse and validate the JWT
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Verify the token signing method is RS256
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return getPublicKey(token)
		})

		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid token: " + err.Error()})
			c.Abort()
			return
		}

		if !token.Valid {
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(401, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		// Verify token hasn't expired
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				c.JSON(401, gin.H{"error": "Token has expired"})
				c.Abort()
				return
			}
		}

		// Verify audience
		if aud, ok := claims["aud"].([]interface{}); ok {
			validAud := false
			for _, a := range aud {
				if a.(string) == "https://dev-lk0vcub54idn0l5c.us.auth0.com/api/v2/" {
					validAud = true
					break
				}
			}
			if !validAud {
				c.JSON(401, gin.H{"error": "Invalid token audience"})
				c.Abort()
				return
			}
		}

		// Verify issuer
		if iss, ok := claims["iss"].(string); ok {
			if iss != "https://dev-lk0vcub54idn0l5c.us.auth0.com/" {
				c.JSON(401, gin.H{"error": "Invalid token issuer"})
				c.Abort()
				return
			}
		}

		// Store user ID in context
		if sub, ok := claims["sub"].(string); ok {
			c.Set("userID", sub)
		} else {
			c.JSON(401, gin.H{"error": "Invalid token subject"})
			c.Abort()
			return
		}

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

	// Drop existing tables
	db.Migrator().DropTable(&NutritionEntry{}, &DailyCalorieLimit{}, &Weight{})

	// Create tables
	db.AutoMigrate(&NutritionEntry{}, &DailyCalorieLimit{}, &Weight{})
}

func initOAuth2Config() {
	oauth2Config = OAuth2Config{
		ClientID:     os.Getenv("AUTH0_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTH0_CLIENT_SECRET"),
		RedirectURI:  os.Getenv("AUTH0_REDIRECT_URI"),
		AuthURL:      "https://dev-lk0vcub54idn0l5c.us.auth0.com/authorize",
		TokenURL:     "https://dev-lk0vcub54idn0l5c.us.auth0.com/oauth/token",
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
	}
}

func handleOAuth2Authorize(c *gin.Context) {
	state := uuid.New().String()
	authURL := fmt.Sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s",
		oauth2Config.AuthURL,
		oauth2Config.ClientID,
		url.QueryEscape(oauth2Config.RedirectURI),
		url.QueryEscape(strings.Join(oauth2Config.Scopes, " ")),
		state,
	)
	c.JSON(http.StatusOK, gin.H{
		"auth_url": authURL,
		"state":    state,
	})
}

func handleOAuth2Callback(c *gin.Context) {
	code := c.Query("code")
	// state := c.Query("state")  // Commented out until we implement state verification

	// Exchange code for token
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", oauth2Config.ClientID)
	data.Set("client_secret", oauth2Config.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", oauth2Config.RedirectURI)

	resp, err := http.PostForm(oauth2Config.TokenURL, data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange code for token"})
		return
	}
	defer resp.Body.Close()

	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse token response"})
		return
	}

	c.JSON(http.StatusOK, tokenResponse)
}

func handleUserInfo(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No authorization header"})
		return
	}

	// Extract token
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header"})
		return
	}

	// Verify token and get claims
	token, err := jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
		return getPublicKey(token)
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
		return
	}

	// Return user info from token claims
	c.JSON(http.StatusOK, gin.H{
		"sub": claims["sub"],
		"email": claims["email"],
		"name": claims["name"],
		"picture": claims["picture"],
	})
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
	config.AllowOrigins = []string{"http://localhost:8080"}
	config.AllowCredentials = true
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	config.ExposeHeaders = []string{"Content-Length", "Authorization"}
	r.Use(cors.New(config))

	// OAuth2 endpoints
	oauth := r.Group("/oauth2")
	{
		oauth.GET("/authorize", handleOAuth2Authorize)
		oauth.GET("/callback", handleOAuth2Callback)
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
