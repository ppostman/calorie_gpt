# Calorie GPT API

A RESTful API service for tracking daily calorie and nutrition intake, designed to integrate with GPT applications.

## Features

- Track daily food intake with detailed nutrition information
- Set base calorie limits and track additional workout calories
- Automatically calculate remaining calories
- Store calories, protein, carbs, and fat for each entry
- Query entries by date
- Full CRUD operations for nutrition entries
- PostgreSQL database for scalable deployment

## API Endpoints

- `POST /entries` - Create a new nutrition entry
- `GET /entries` - Get all entries
- `GET /entries/:id` - Get a specific entry
- `GET /entries/date/:date` - Get entries for a specific date
- `PUT /entries/:id` - Update an entry
- `DELETE /entries/:id` - Delete an entry

## Setup

1. Install Go (1.21 or later)
2. Install PostgreSQL
3. Clone this repository
4. Set up your environment variables in `.env`:
   ```env
   PORT=8080
   DB_HOST=localhost
   DB_USER=your_username
   DB_PASSWORD=your_password
   DB_NAME=calorie_gpt
   DB_PORT=5432
   ```
   For production, you can just set the `DATABASE_URL`:
   ```env
   DATABASE_URL=postgresql://user:password@host:port/dbname
   ```
5. Install dependencies:
   ```bash
   go mod download
   ```
6. Create the PostgreSQL database:
   ```bash
   createdb calorie_gpt
   ```
7. Run the server:
   ```bash
   go run main.go
   ```

The server will start on port 8080 by default.

## Example Request

Create a new entry:

```bash
curl -X POST http://localhost:8080/entries \
-H "Content-Type: application/json" \
-d '{
    "date": "2025-02-16",
    "base_calorie_limit": 2000,
    "workout_calories": 300,
    "food": "Chicken Salad",
    "calories": 350,
    "protein": 25,
    "carbs": 15,
    "fat": 20,
    "description": "Grilled chicken breast with mixed greens"
}'
```

The API will automatically calculate the `calories_remaining` field (in this case: 1950 calories = 2000 base + 300 workout - 350 food calories)

## Database

The API uses PostgreSQL as the database. The database schema will be automatically created when you first run the application using GORM's auto-migration feature.
