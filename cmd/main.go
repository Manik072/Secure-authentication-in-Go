package main

import (
	"log"

	"secure-auth/config"
	"secure-auth/db"
	"secure-auth/handlers"
	"secure-auth/repository"
	"secure-auth/service"

	"github.com/gofiber/fiber/v2"
)

func main() {
	cfg := config.LoadConfig()

	client, err := db.ConnectMongo(cfg.MongoURI)
	if err != nil {
		log.Fatalf("failed to connect to mongo: %v", err)
	}

	mongoDB := client.Database("secure_auth")
	repo := repository.NewUserRepository(mongoDB, "users")
	authService := service.NewAuthService(*repo, cfg.JWTSecret, cfg.JWTRefreshSecret)

	app := fiber.New()
	handlers.SetupRoutes(app, authService, cfg)

	log.Printf("listening on :%s", cfg.Port)
	if err := app.Listen(":" + cfg.Port); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
