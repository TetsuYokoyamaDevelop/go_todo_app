package main

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// Todo モデル
type Todo struct {
	ID        uint       `gorm:"primaryKey"`
	Title     string     `json:"title"`
	Completed bool       `json:"completed"`
	DueDate   *time.Time `json:"due_date" gorm:"default:null"`
	UserID    uint       `json:"user_id"`           // Userへの外部キー
	User      User       `gorm:"foreignKey:UserID"` // Userとの関連
}

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Email    string `json:"email"`
	Password string `json:"-"`
}

// DB 変数
var db *gorm.DB

func init() {
	// SQLite データベースを開く
	var err error
	dsn := "todo_user:password@tcp(127.0.0.1:3306)/todo_app?charset=utf8mb4&parseTime=True&loc=Local"
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// `todos` テーブルを作成
	db.AutoMigrate(&Todo{})
	db.AutoMigrate(&User{})
}

func userEmail(c *gin.Context) (string, bool, string) {
	userEmail, exists := c.Get("userEmail")
	if !exists {
		return "", false, "User not authenticated"
	}
	return userEmail.(string), true, ""
}

// TODO 一覧を取得
func getTodos(c *gin.Context) {
	var todos []Todo
	// JWTトークンからユーザー情報を取得
	email, ok, err := userEmail(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err})
		return
	}

	var user User
	if err := db.Where("email = ?", email).First(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return
	}

	// クエリパラメータから検索キーワードを取得
	search := c.Query("search")

	// クエリパラメータを使用して検索
	query := db.Preload("User").Where("user_id = ?", user.ID)
	if search != "" {
		query = query.Where("title LIKE ?", "%"+search+"%")
	}
	query.Order("due_date ASC").Find(&todos)

	c.JSON(http.StatusOK, todos)
}

func getOverdueTodos(c *gin.Context) {
	var todos []Todo

	email, ok, err := userEmail(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err})
		return
	}

	var user User
	if err := db.Where("email = ?", email).First(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return
	}

	db.Preload("User").Where("user_id = ? AND due_date IS NOT NULL AND due_date < ?", user.ID, time.Now()).Find(&todos)
	c.JSON(http.StatusOK, todos)
}

func getHasDueDateTodos(c *gin.Context) {
	var todos []Todo
	email, ok, err := userEmail(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err})
		return
	}

	var user User
	if err := db.Where("email = ?", email).First(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return
	}

	db.Preload("User").Where("user_id = ? AND due_date IS NOT NULL", user.ID).Find(&todos)
	c.JSON(http.StatusOK, todos)
}

// TODO を作成
func createTodo(c *gin.Context) {
	var newTodo Todo
	if err := c.ShouldBindJSON(&newTodo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// JWTトークンからユーザー情報を取得
	userEmail, ok, err := userEmail(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err})
		return
	}

	var user User
	if err := db.Where("email = ?", userEmail).First(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return
	}

	newTodo.UserID = user.ID

	// Todoを作成
	if err := db.Create(&newTodo).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating TODO"})
		return
	}

	// 関連するUser情報をロード
	if err := db.Preload("User").First(&newTodo, newTodo.ID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error loading user data"})
		return
	}

	c.JSON(http.StatusCreated, newTodo)
}

// TODO を更新
func updateTodo(c *gin.Context) {
	var todo Todo
	email, ok, err := userEmail(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err})
		return
	}
	if err := db.Preload("User").Where("user_id = ?", email).First(&todo, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "TODO not found"})
		return
	}
	if err := c.ShouldBindJSON(&todo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	db.Save(&todo)
	c.JSON(http.StatusOK, todo)
}

// TODO を削除
func deleteTodo(c *gin.Context) {
	var todo Todo
	email, ok, err := userEmail(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err})
		return
	}
	if err := db.Preload("User").Where("user_id = ?", email).First(&todo, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "TODO not found"})
		return
	}
	db.Delete(&todo)
	c.JSON(http.StatusOK, gin.H{"message": "TODO deleted"})
}

func register(c *gin.Context) {
	var user User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error while hashing password"})
		return
	}
	user.Password = string(hashedPassword)

	if err := db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error while registering user"})
		return
	}
	c.JSON(http.StatusOK, user)
}

func login(c *gin.Context) {
	var user User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var foundUser User
	if err := db.Where("email = ?", user.Email).First(&foundUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error while logging in"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(user.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
	})

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "JWT Secret not found"})
		return
	}

	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error while generating token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Authorizationヘッダーからトークンを取得
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		// "Bearer "を取り除く
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// JWT_SECRETを取得
		jwtSecret := os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "JWT Secret not found"})
			c.Abort()
			return
		}

		// トークンを検証
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// トークンが有効であれば、ユーザーのメールをコンテキストに保存
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if email, ok := claims["email"].(string); ok {
				c.Set("userEmail", email)
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
				c.Abort()
				return
			}
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func main() {
	r := gin.Default()

	// API ルート
	r.POST("/register", register)
	r.POST("/login", login)

	// 認証が必要なルート
	auth := r.Group("/")
	auth.Use(AuthMiddleware())
	{
		auth.GET("/todos", getTodos)
		auth.POST("/todos", createTodo)
		auth.PUT("/todos/:id", updateTodo)
		auth.DELETE("/todos/:id", deleteTodo)
		auth.GET("todos/overdue", getOverdueTodos)
		auth.GET("todos/has_due_date", getHasDueDateTodos)
	}

	r.Run(":8080") // サーバー起動
}
