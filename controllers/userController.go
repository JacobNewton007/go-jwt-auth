package controllers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/JacobNewton007/go-jwt-auth/database"
	"github.com/JacobNewton007/go-jwt-auth/helpers"
	"github.com/JacobNewton007/go-jwt-auth/models"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)



var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()
func HashPassword(password string) string {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(hashedPassword)
} 

func VerifyPassword(userPassword, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	var msg string

	if err != nil {
		msg = fmt.Sprintf("password is incorrect")
	}
	return check, msg
}

  

func Signup() gin.HandlerFunc{
	return func(ctx *gin.Context) {
		var contx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User

		if err := ctx.BindJSON(&user); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
			return
		}
		validationErr := validate.Struct(user)
		if validationErr != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error":validationErr.Error()})
			return
		}
		count, err := userCollection.CountDocuments(contx, bson.M{"email": user.Email})
		defer cancel()
		if err != nil {
			log.Fatal(err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the email"})
		}

		password  := HashPassword(*user.Password)
		user.Password = &password
		count, err = userCollection.CountDocuments(contx, bson.M{"phone": user.Phone})
		defer cancel()
		if err != nil {
			log.Fatal(err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for phone number"})
		}
		if count > 0 {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "this email or password already exist"}) 
		}
		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()
		token, refreshToken, _ := helpers.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, *user.User_type, *&user.User_id)
		user.Token = &token
		user.Refresh_token = &refreshToken

		resultInsertionNumber, inserErr := userCollection.InsertOne(ctx, user)
		if inserErr != nil {
			msg := fmt.Sprintf("User item was not created")
			ctx.JSON(http.StatusInternalServerError, gin.H{"error":msg})
		}
		defer cancel()
		ctx.JSON(http.StatusCreated, gin.H{"status": http.StatusOK, "message": "successfully created an account", "data": resultInsertionNumber}) 
	}
}

func Login() gin.HandlerFunc{
	return func(ctx *gin.Context) {
		var contx, cancel = context.WithTimeout(context.Background(), 100 *time.Second)
		var user models.User
		var founduser models.User

		if err := ctx.BindJSON(&user); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
			return
		}

		err := userCollection.FindOne(contx, bson.M{"email":user.Email}).Decode(&founduser)
		defer cancel()
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error":"email or password is incorrect"})
			return 
		}

		passwordIsValid, _ := VerifyPassword(*user.Password, *founduser.Password)
		defer cancel()
		if !passwordIsValid{
			ctx.JSON(http.StatusInternalServerError, gin.H{"error":"user not found"})
		}
		if founduser.Email == nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error":"user not found"})
		}
		token, refreshToken, _ := helpers.GenerateAllTokens(*founduser.Email, *founduser.First_name, *founduser.Last_name, *founduser.User_type, *&founduser.User_id)
		helpers.UpdateAllTokens(token, refreshToken, founduser.User_id)
		err = userCollection.FindOne(contx, bson.M{"user_id":founduser.User_id}).Decode(&founduser)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error":err.Error()})
			return
		}
		ctx.JSON(http.StatusOK, founduser)
	}
}

func GetUsers() gin.HandlerFunc{
	return func(ctx *gin.Context) {
		if err := helpers.CheckUserType(ctx, "ADMIN"); err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		var contx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		recordPerPage, err := strconv.Atoi(ctx.Query("recordPerPage"))
		if err != nil || recordPerPage < 1 {
			recordPerPage = 10
		}
		page, err1 := strconv.Atoi(ctx.Query("page"))
		if err1 != nil || page < 1 {
			page = 1
		}
		startIndex := (page - 1) * recordPerPage
		startIndex, err = strconv.Atoi(ctx.Query("startIndex"))

		matchStage := bson.D{{"$match", bson.D{{}}}}
		groupStage := bson.D{{"$group", bson.D{
			{"_id", bson.D{{"_id", "null"}}},
			{"total_count", bson.D{{"$sum", 1}}},
			{"data", bson.D{{"$push", "$$ROOT"}}}}}}
		projectStage := bson.D{
			{"$project", bson.D{
				{"_id", 0},
				{"total_count", 1},
				{"user_items", bson.D{{"$slice", []interface{}{"$data", startIndex, recordPerPage}}}},}}}
		result, err := userCollection.Aggregate(contx, mongo.Pipeline{
			matchStage, groupStage, projectStage})
		defer cancel()
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error":"error ocured while listing user items"})
		}
		var allUsers []bson.M
		if err := result.All(contx, &allUsers); err != nil {
			log.Fatal(err)
		}
		ctx.JSON(http.StatusOK, allUsers[0])}
}

func GetUser() gin.HandlerFunc{
	return func(ctx *gin.Context) {
		userId := ctx.Param("user_id")

		 if err := helpers.MatchUserTypeTOUid(ctx, userId); err != nil {
			 ctx.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
			 return
		 }
		var contx, cancel = context.WithTimeout(context.Background(), 100 * time.Second)

		var user models.User
		err := userCollection.FindOne(contx, bson.M{"user_id": userId}).Decode(&user)
		defer cancel()
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		ctx.JSON(http.StatusOK, user)
	}
}


