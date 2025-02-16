package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// @title Calorie GPT API
// @version 1.0
// @description API for tracking daily calorie and nutrition intake with GPT integration
// @host localhost:8080
// @BasePath /

type NutritionEntry struct {
	gorm.Model
	Date              string  `json:"date"`
	BaseCalorieLimit  float64 `json:"base_calorie_limit"`
	WorkoutCalories   float64 `json:"workout_calories"`
	CaloriesRemaining float64 `json:"calories_remaining"`
	Food              string  `json:"food"`
	Calories          float64 `json:"calories"`
	Protein           float64 `json:"protein"`
	Carbs             float64 `json:"carbs"`
	Fat               float64 `json:"fat"`
	Description       string  `json:"description"`
}

var db *gorm.DB

// @Summary Create a new nutrition entry
// @Description Create a new nutrition entry with calorie tracking
// @Accept json
// @Produce json
// @Param entry body NutritionEntry true "Nutrition Entry"
// @Success 201 {object} NutritionEntry
// @Failure 400 {object} map[string]string
// @Router /entries [post]
func createEntry(c *gin.Context) {
	var entry NutritionEntry
	if err := c.ShouldBindJSON(&entry); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Calculate calories remaining
	totalAvailableCalories := entry.BaseCalorieLimit + entry.WorkoutCalories
	entry.CaloriesRemaining = totalAvailableCalories - entry.Calories

	db.Create(&entry)
	c.JSON(201, entry)
}

// @Summary Get all nutrition entries
// @Description Get a list of all nutrition entries
// @Produce json
// @Success 200 {array} NutritionEntry
// @Router /entries [get]
func getEntries(c *gin.Context) {
	var entries []NutritionEntry
	db.Find(&entries)
	c.JSON(200, entries)
}

// @Summary Get a specific nutrition entry
// @Description Get a nutrition entry by its ID
// @Produce json
// @Param id path int true "Entry ID"
// @Success 200 {object} NutritionEntry
// @Failure 404 {object} map[string]string
// @Router /entries/{id} [get]
func getEntry(c *gin.Context) {
	id := c.Param("id")
	var entry NutritionEntry
	
	if err := db.First(&entry, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "Entry not found"})
		return
	}
	
	c.JSON(200, entry)
}

// @Summary Get entries by date
// @Description Get all nutrition entries for a specific date
// @Produce json
// @Param date path string true "Date (YYYY-MM-DD)"
// @Success 200 {array} NutritionEntry
// @Router /entries/date/{date} [get]
func getEntriesByDate(c *gin.Context) {
	date := c.Param("date")
	var entries []NutritionEntry
	
	db.Where("date = ?", date).Find(&entries)
	c.JSON(200, entries)
}

// @Summary Update a nutrition entry
// @Description Update an existing nutrition entry
// @Accept json
// @Produce json
// @Param id path int true "Entry ID"
// @Param entry body NutritionEntry true "Updated Nutrition Entry"
// @Success 200 {object} NutritionEntry
// @Failure 404 {object} map[string]string
// @Router /entries/{id} [put]
func updateEntry(c *gin.Context) {
	id := c.Param("id")
	var entry NutritionEntry
	
	if err := db.First(&entry, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "Entry not found"})
		return
	}
	
	if err := c.ShouldBindJSON(&entry); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	db.Save(&entry)
	c.JSON(200, entry)
}

// @Summary Delete a nutrition entry
// @Description Delete a nutrition entry by its ID
// @Produce json
// @Param id path int true "Entry ID"
// @Success 200 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /entries/{id} [delete]
func deleteEntry(c *gin.Context) {
	id := c.Param("id")
	var entry NutritionEntry
	
	if err := db.First(&entry, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "Entry not found"})
		return
	}
	
	db.Delete(&entry)
	c.JSON(200, gin.H{"message": "Entry deleted successfully"})
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
	db.AutoMigrate(&NutritionEntry{})
}

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Initialize database
	initDB()

	// Setup router
	r := gin.Default()

	// Routes
	r.POST("/entries", createEntry)
	r.GET("/entries", getEntries)
	r.GET("/entries/:id", getEntry)
	r.GET("/entries/date/:date", getEntriesByDate)
	r.PUT("/entries/:id", updateEntry)
	r.DELETE("/entries/:id", deleteEntry)

	// Swagger documentation endpoint
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Run server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}
