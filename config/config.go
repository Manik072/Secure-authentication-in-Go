package config

import (
	"os"
)

type Config struct {
	MongoURI         string
	JWTSecret        string
	JWTRefreshSecret string
	Port             string
}

func LoadConfig() *Config {
	cfg := &Config{
		MongoURI:         getEnv("MONGO_URI", "mongodb://localhost:27017/testFiber"),
		JWTSecret:        getEnv("JWT_SECRET", "supersecretjwtkey"),
		JWTRefreshSecret: getEnv("JWT_REFRESH_SECRET", "superrefreshsecretkey"),
		Port:             getEnv("PORT", "8080"),
	}
	return cfg
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
