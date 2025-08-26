package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"secure-auth/models"
	"secure-auth/repository"
	"secure-auth/utils"
)

type AuthService struct {
	userRepo      repository.UserRepository
	jwtSecret     string
	refreshSecret string
	accessTTL     time.Duration
}

func NewAuthService(userRepo repository.UserRepository, jwtSecret string, refreshSecret string) *AuthService {
	return &AuthService{
		userRepo:      userRepo,
		jwtSecret:     jwtSecret,
		refreshSecret: refreshSecret,
		accessTTL:     15 * time.Minute,
	}
}

func (s *AuthService) Register(ctx context.Context, name, email, password string) (*models.User, error) {
	_, err := s.userRepo.FindByEmail(ctx, email)
	if err == nil {
		return nil, errors.New("email already exists")
	}

	hashed, err := utils.HashPassword(password)
	if err != nil {
		return nil, err
	}

	user := &models.User{
		Name:     name,
		Email:    email,
		Password: hashed,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *AuthService) Login(ctx context.Context, email, password string) (string, *models.User, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return "", nil, errors.New("invalid email or password")
	}

	if err := utils.CheckPassword(user.Password, password); err != nil {
		return "", nil, errors.New("invalid email or password")
	}

	token, err := utils.GenerateToken(user.ID.Hex(), s.jwtSecret, s.accessTTL)
	if err != nil {
		return "", nil, err
	}

	return token, user, nil
}

func (s *AuthService) GenerateRefresh(ctx context.Context, userID string) (string, error) {
	randTok, err := utils.GenerateRandomToken(32)
	if err != nil {
		return "", err
	}
	token := userID + ":" + randTok
	hash, err := utils.HashToken(randTok)
	if err != nil {
		return "", err
	}
	if err := s.userRepo.UpdateRefreshHash(ctx, userID, hash); err != nil {
		return "", err
	}
	return token, nil
}

func (s *AuthService) RefreshAccess(ctx context.Context, refreshToken string) (string, string, *models.User, error) {
	parts := strings.SplitN(refreshToken, ":", 2)
	if len(parts) != 2 {
		return "", "", nil, errors.New("invalid refresh token format")
	}
	sub := parts[0]
	raw := parts[1]

	user, err := s.userRepo.FindByID(ctx, sub)
	if err != nil {
		return "", "", nil, err
	}
	if user.RefreshTokenHash == "" {
		return "", "", nil, errors.New("no refresh token stored")
	}
	if !utils.CompareTokenHash(user.RefreshTokenHash, raw) {
		return "", "", nil, errors.New("refresh token mismatch")
	}
	accessToken, err := utils.GenerateToken(user.ID.Hex(), s.jwtSecret, s.accessTTL)
	if err != nil {
		return "", "", nil, err
	}
	newRefresh, err := s.GenerateRefresh(ctx, user.ID.Hex())
	if err != nil {
		return "", "", nil, err
	}
	return accessToken, newRefresh, user, nil
}

func (s *AuthService) Logout(ctx context.Context, userID string) error {
	return s.userRepo.ClearRefreshHash(ctx, userID)
}
