package main

import (
	"os"
	"gopkg.in/gin-gonic/gin.v1"
	"gopkg.in/mgo.v2"
	"./config"
	"./input"
	"./models"
	"net/http"
)

var (
	mongo *mgo.Session
)

func initDB() {
	configs, _ := config.ReadConfig("config.json")

	s, err := mgo.Dial("mongodb://"+configs.DB_HOST)

	// Check if connection error, is mongo running?
	if err != nil {
		panic(err)
	}
	mongo = s
}

func main(){
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	router := gin.New()
        router.Use(gin.Logger())
	router.Use(gin.Recovery())

	initDB()

	//router.POST("/login", LoginHandler)
	//router.POST("/register", RegisterHandler)

}
