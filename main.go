package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

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

	// Run server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}

func initDB() {
	var err error
	db, err = gorm.Open(sqlite.Open("nutrition.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Migrate the schema
	db.AutoMigrate(&NutritionEntry{})
}

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

func getEntries(c *gin.Context) {
	var entries []NutritionEntry
	db.Find(&entries)
	c.JSON(200, entries)
}

func getEntry(c *gin.Context) {
	id := c.Param("id")
	var entry NutritionEntry
	
	if err := db.First(&entry, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "Entry not found"})
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
