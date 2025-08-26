package handlers

import (
	"context"
	"log"
	"time"

	"secure-auth/config"
	"secure-auth/middleware"
	"secure-auth/service"

	"github.com/gofiber/fiber/v2"
)

type AuthHandler struct {
	authService *service.AuthService
	cfg         *config.Config
}

// Constructor
func NewAuthHandler(authService *service.AuthService, cfg *config.Config) *AuthHandler {
	return &AuthHandler{authService: authService, cfg: cfg}
}

// SetupRoutes sets Fiber routes
func SetupRoutes(app *fiber.App, authService *service.AuthService, cfg *config.Config) {
	handler := NewAuthHandler(authService, cfg)

	api := app.Group("/api/v1")
	api.Post("/register", handler.Register)
	api.Post("/login", handler.Login)
	api.Post("/refresh", handler.Refresh)
	api.Post("/logout", handler.Logout)

	protected := api.Group("/user")
	protected.Use(middleware.AuthMiddleware(cfg))
	protected.Get("/me", handler.Me)
}

// Register endpoint
func (h *AuthHandler) Register(c *fiber.Ctx) error {
	type req struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var body req
	if err := c.BodyParser(&body); err != nil {
		log.Printf("Register BodyParser error: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request", "details": err.Error()})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user, err := h.authService.Register(ctx, body.Name, body.Email, body.Password)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"id":    user.ID.Hex(),
		"name":  user.Name,
		"email": user.Email,
	})
}

// Login endpoint
func (h *AuthHandler) Login(c *fiber.Ctx) error {
	type req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var body req
	if err := c.BodyParser(&body); err != nil {
		log.Printf("Login BodyParser error: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request", "details": err.Error()})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	token, user, err := h.authService.Login(ctx, body.Email, body.Password)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	// generate refresh token and store hash
	refresh, err := h.authService.GenerateRefresh(ctx, user.ID.Hex())
	if err != nil {
		log.Printf("GenerateRefresh error for user %s: %v", user.ID.Hex(), err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create refresh token", "details": err.Error()})
	}

	// set cookies - HttpOnly, Secure should be true in production
	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    token,
		Expires:  time.Now().Add(15 * time.Minute),
		HTTPOnly: true,
		Secure:   false,
		SameSite: "Lax",
	})
	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    refresh,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
		HTTPOnly: true,
		Secure:   false,
		SameSite: "Lax",
	})

	return c.JSON(fiber.Map{
		"user": fiber.Map{
			"id":    user.ID.Hex(),
			"name":  user.Name,
			"email": user.Email,
		},
	})
}

// Refresh exchanges a valid refresh cookie for a new access (and rotated refresh) token
func (h *AuthHandler) Refresh(c *fiber.Ctx) error {
	refresh := c.Cookies("refresh_token")
	if refresh == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing refresh token"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	access, newRefresh, _, err := h.authService.RefreshAccess(ctx, refresh)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	c.Cookie(&fiber.Cookie{Name: "access_token", Value: access, Expires: time.Now().Add(15 * time.Minute), HTTPOnly: true, Secure: false, SameSite: "Lax"})
	c.Cookie(&fiber.Cookie{Name: "refresh_token", Value: newRefresh, Expires: time.Now().Add(7 * 24 * time.Hour), HTTPOnly: true, Secure: false, SameSite: "Lax"})

	return c.JSON(fiber.Map{"message": "token refreshed"})
}

// Logout clears refresh token server-side and clears cookies
func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	userID := c.Locals("user_id")
	if userID == nil {
		// still clear cookies on client
		c.ClearCookie("access_token")
		c.ClearCookie("refresh_token")
		return c.SendStatus(fiber.StatusOK)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = h.authService.Logout(ctx, userID.(string))
	c.ClearCookie("access_token")
	c.ClearCookie("refresh_token")
	return c.JSON(fiber.Map{"message": "logged out"})
}

// Me endpoint (protected)
func (h *AuthHandler) Me(c *fiber.Ctx) error {
	userID := c.Locals("user_id")
	if userID == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"})
	}

	return c.JSON(fiber.Map{"user_id": userID})
}
