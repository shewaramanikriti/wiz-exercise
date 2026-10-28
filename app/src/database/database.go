package database

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var Client *mongo.Client = CreateMongoClient()

func CreateMongoClient() *mongo.Client {
	godotenv.Overload()
	MongoDbURI := os.Getenv("MONGODB_URI")
	client, err := mongo.NewClient(options.Client().ApplyURI(MongoDbURI))
	if err != nil {
		log.Fatal("Invalid MongoDB connection configuration")
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal("MongoDB client initialization failed")
	}
	defer cancel()
	// Connect is lazy. Do not claim a successful database query or log the URI.
	log.Println("MongoDB client configured")
	return client
}

func OpenCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	return client.Database("go-mongodb").Collection(collectionName)
}
