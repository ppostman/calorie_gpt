package main

import (
	"fmt"
	"log"
	"os"
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type DailyCalorieLimit struct {
	gorm.Model
	Date            string  `json:"date"`
	BaseCalories    float64 `json:"base_calories"`
	WorkoutCalories float64 `json:"workout_calories"`
}

type NutritionEntry struct {
	gorm.Model
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
	gorm.Model
	Date   string  `json:"date" gorm:"not null"`
	Weight float64 `json:"weight" gorm:"not null"`
	Notes  string  `json:"notes"`
}

var db *gorm.DB

func createDailyLimit(c *gin.Context) {
	var limit DailyCalorieLimit
	if err := c.ShouldBindJSON(&limit); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Check if a limit already exists for this date
	var existingLimit DailyCalorieLimit
	if result := db.Where("date = ?", limit.Date).First(&existingLimit); result.Error == nil {
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
	var limit DailyCalorieLimit
	
	if err := db.Where("date = ?", date).First(&limit).Error; err != nil {
		c.JSON(404, gin.H{"error": "Daily limit not found"})
		return
	}
	
	c.JSON(200, limit)
}

func createEntry(c *gin.Context) {
	var entry NutritionEntry
	if err := c.ShouldBindJSON(&entry); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	db.Create(&entry)
	c.JSON(201, entry)
}

func getEntries(c *gin.Context) {
	var entries []NutritionEntry
	db.Find(&entries)
	c.JSON(200, entries)
}

func getEntry(c *gin.Context) {
	id := c.Param("id")
	var entry NutritionEntry
	
	if err := db.First(&entry, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
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
	var entries []NutritionEntry
	
	db.Where("date = ?", date).Find(&entries)
	c.JSON(200, entries)
}

func getDailyCalories(c *gin.Context) {
	date := c.Param("date")
	
	// Get daily limit
	var limit DailyCalorieLimit
	if err := db.Where("date = ?", date).First(&limit).Error; err != nil {
		c.JSON(404, gin.H{"error": "Daily limit not found for this date"})
		return
	}
	
	// Get all entries for the date
	var entries []NutritionEntry
	db.Where("date = ?", date).Find(&entries)
	
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
	var entry NutritionEntry
	
	if err := db.First(&entry, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(404, gin.H{"error": "Entry not found"})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	if err := c.ShouldBindJSON(&entry); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	db.Save(&entry)
	c.JSON(200, entry)
}

func deleteEntry(c *gin.Context) {
	id := c.Param("id")
	var entry NutritionEntry
	
	if err := db.First(&entry, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(404, gin.H{"error": "Entry not found"})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
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

	if err := db.Create(&weight).Error; err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(201, weight)
}

func getWeight(c *gin.Context) {
	id := c.Param("id")
	var weight Weight

	if err := db.First(&weight, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
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
	var weights []Weight

	if err := db.Where("date = ?", date).Find(&weights).Error; err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, weights)
}

func updateWeight(c *gin.Context) {
	id := c.Param("id")
	var weight Weight

	if err := db.First(&weight, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(404, gin.H{"error": "Weight record not found"})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
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
	var weight Weight

	if err := db.First(&weight, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(404, gin.H{"error": "Weight record not found"})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if err := db.Delete(&weight).Error; err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "Weight record deleted successfully"})
}

func initDB() {
	var err error

	// Get database connection details from environment variables
	dbHost := os.Getenv("DB_HOST")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbPort := os.Getenv("DB_PORT")

	// If DATABASE_URL is provided (e.g., in production), use it instead
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
			dbHost, dbUser, dbPassword, dbName, dbPort)
	}

	// Connect to PostgreSQL
	db, err = gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Migrate the schema
	db.AutoMigrate(&NutritionEntry{}, &DailyCalorieLimit{}, &Weight{})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		expectedAPIKey := os.Getenv("API_KEY")

		if apiKey == "" {
			c.JSON(401, gin.H{"error": "API key is required"})
			c.Abort()
			return
		}

		if apiKey != expectedAPIKey {
			c.JSON(401, gin.H{"error": "Invalid API key"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Initialize database
	initDB()

	// Initialize Gin router
	r := gin.Default()

	// Enable CORS
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, X-API-Key")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Apply auth middleware to all routes
	authorized := r.Group("/")
	authorized.Use(authMiddleware())
	{
		// Daily Limits routes
		authorized.POST("/daily-limits", createDailyLimit)
		authorized.GET("/daily-limits/:date", getDailyLimit)

		// Nutrition Entry routes
		authorized.POST("/entries", createEntry)
		authorized.GET("/entries", getEntries)
		authorized.GET("/entries/:id", getEntry)
		authorized.GET("/entries/date/:date", getEntriesByDate)
		authorized.PUT("/entries/:id", updateEntry)
		authorized.DELETE("/entries/:id", deleteEntry)

		// Calorie Calculation route
		authorized.GET("/calories/:date", getDailyCalories)

		// Weight tracking endpoints
		authorized.POST("/weights", createWeight)
		authorized.GET("/weights/:id", getWeight)
		authorized.GET("/weights/date/:date", getWeightsByDate)
		authorized.PUT("/weights/:id", updateWeight)
		authorized.DELETE("/weights/:id", deleteWeight)
	}

	// Run server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}
