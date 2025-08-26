package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID               primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name             string             `bson:"name" json:"name"`
	Email            string             `bson:"email" json:"email"`
	Password         string             `bson:"password" json:"-"`
	RefreshTokenHash string             `bson:"refresh_hash,omitempty" json:"-"`
	Created          time.Time          `bson:"created" json:"created"`
	Updated          time.Time          `bson:"updated" json:"updated"`
}
