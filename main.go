package main

import (
	"gopkg.in/gin-gonic/gin.v1"
	"gopkg.in/mgo.v2"
	"./config"
	"./input"
	"./models"
	"time"
	"net/http"
	"gopkg.in/mgo.v2/bson"
	"golang.org/x/crypto/bcrypt"
	"github.com/satori/go.uuid"
	jwt "github.com/dgrijalva/jwt-go"
	"log"
	"github.com/dgrijalva/jwt-go/request"
)

const (
	JWTSigningKey string        = "nirmalvatsyayan"
	ExpireTime    time.Duration = time.Minute * 60 * 24 * 30
	Realm         string        = "jwt auth"
)

var (
	mongo *mgo.Session
	db string
	currentUser models.User
)

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}


func AbortWithError(c *gin.Context, code int, message string) {
	c.Header("WWW-Authenticate", "JWT realm="+Realm)
	c.JSON(code, gin.H{
		"code":    code,
		"message": message,
	})
	c.Abort()
}



func RegisterHandler(c *gin.Context) {
	var form input.Register

	if c.BindJSON(&form) != nil {
		AbortWithError(c, http.StatusBadRequest, "Missing name or usename or password")
		return
	}

	total_count, _ := mongo.DB("test_db").C("user_profile").Find(bson.M{"username":form.Username}).Count()

	if total_count > 0 {
		AbortWithError(c, http.StatusBadRequest, "Username is already exist")
		return
	}

	userId := uuid.NewV4().String()

	if digest, err := bcrypt.GenerateFromPassword([]byte(form.Password), bcrypt.DefaultCost); err != nil {
		AbortWithError(c, http.StatusInternalServerError, err.Error())
		return
	} else {
		form.Password = string(digest)
	}

	user_obj := models.User{
		ID:       userId,
		Name: form.Name,
		Username: form.Username,
		Password: form.Password,
	}

	if err := mongo.DB(db).C("user_profile").Insert(user_obj); err != nil {
		AbortWithError(c, http.StatusInternalServerError, err.Error())
		return
	}

	expire := time.Now().Add(ExpireTime)

	// Create the token
	token := jwt.New(jwt.SigningMethodHS256)
	// Set some claims
	claims := make(jwt.MapClaims)
	claims["id"] = user_obj.ID
	claims["exp"] = expire.Unix()
	token.Claims = claims
	// Sign and get the complete encoded token as a string
	tokenString, _ := token.SignedString([]byte(JWTSigningKey))

	c.JSON(http.StatusOK, gin.H{
		"message": "ok",
		"token": tokenString,
	})
}


func LoginHandler(c *gin.Context) {
	var form input.Login
	var user models.User

	if c.BindJSON(&form) != nil {
		AbortWithError(c, http.StatusBadRequest, "Missing usename or password")
		return
	}

	err := mongo.DB("test_db").C("user_profile").Find(bson.M{"username":form.Username}).One(&user)

	if err != nil {
		AbortWithError(c, http.StatusInternalServerError, "DB Query Error")
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(form.Password)) != nil {
		AbortWithError(c, http.StatusUnauthorized, "Incorrect Username / Password")
		return
	}

	expire := time.Now().Add(ExpireTime)

	// Create the token
	token := jwt.New(jwt.SigningMethodHS256)
	// Set some claims
	claims := make(jwt.MapClaims)
	claims["id"] = user.ID
	claims["exp"] = expire.Unix()
	token.Claims = claims
	// Sign and get the complete encoded token as a string

	tokenString, err := token.SignedString([]byte(JWTSigningKey))
	if err != nil {
		AbortWithError(c, http.StatusUnauthorized, "Create JWT Token faild")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":  tokenString,
		"expire": expire.Format(time.RFC3339),
	})
}

func RefreshHandler(c *gin.Context) {
	expire := time.Now().Add(ExpireTime)

	// Create the token
	token := jwt.New(jwt.SigningMethodHS256)
	claims := make(jwt.MapClaims)
	claims["id"] = currentUser.ID
	claims["exp"] = expire.Unix()
	token.Claims = claims
	// Set some claims
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString([]byte(JWTSigningKey))

	if err != nil {
		AbortWithError(c, http.StatusUnauthorized, "Create JWT Token faild")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":  tokenString,
		"expire": expire.Format(time.RFC3339),
	})
}

func Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		var user models.User
		token, err := request.ParseFromRequest(c.Request,request.AuthorizationHeaderExtractor, func(token *jwt.Token) (interface{}, error) {
			b := ([]byte(JWTSigningKey))

			return b, nil
		})

		if err != nil {
			AbortWithError(c, http.StatusUnauthorized, "Invaild User Token")
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		log.Printf("Current user id: %s", claims["id"])

		err = mongo.DB("test_db").C("user_profile").Find(bson.M{"id":claims["id"]}).One(&user)

		if err != nil {
			AbortWithError(c, http.StatusInternalServerError, "DB Query Error")
			return
		}

		currentUser = user
	}
}

func initDB() {
	configs, _ := config.ReadConfig("config.json")

	s, err := mgo.Dial("mongodb://"+configs.DB_HOST)

	// Check if connection error, is mongo running?
	if err != nil {
		panic(err)
	}
	mongo = s
	db = configs.DB_NAME
}

func HelloHandler(c *gin.Context) {
	currentTime := time.Now()
	currentTime.Format(time.RFC3339)
	c.JSON(200, gin.H{
		"current_time": currentTime,
		"text":"Hi " + currentUser.Username + ", You are login now.",
	})
}

func main(){
	//port := os.Getenv("PORT")
	//if port == "" {
	//	port = "8000"
	//}
	port := ":8000"

	router := gin.New()
        router.Use(gin.Logger())
	router.Use(gin.Recovery())

	initDB()

	router.POST("/login", LoginHandler)
	router.POST("/register", RegisterHandler)

	auth := router.Group("/auth")
	auth.Use(Auth())
	{
		auth.GET("/hello", HelloHandler)
		auth.GET("/refresh_token", RefreshHandler)
	}

	router.Run(port)

}
