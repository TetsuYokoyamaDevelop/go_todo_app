package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// Todo モデル
type Todo struct {
	ID        uint       `gorm:"primaryKey"`
	Title     string     `json:"title"`
	Completed bool       `json:"completed"`
	DueDate   *time.Time `json:"due_date" gorm:"default:null"`
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
}

// TODO 一覧を取得
func getTodos(c *gin.Context) {
	var todos []Todo
	db.Find(&todos)
	c.JSON(http.StatusOK, todos)
}

func getOverdueTodos(c *gin.Context) {
	var todos []Todo
	db.Where("due_date IS NOT NULL AND due_date < ?", time.Now()).Find(&todos)
	c.JSON(http.StatusOK, todos)
}

func getHasDueDateTodos(c *gin.Context) {
	var todos []Todo
	db.Where("due_date IS NOT NULL").Find(&todos)
	c.JSON(http.StatusOK, todos)
}

// TODO を作成
func createTodo(c *gin.Context) {
	var newTodo Todo
	if err := c.ShouldBindJSON(&newTodo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	db.Create(&newTodo)
	c.JSON(http.StatusCreated, newTodo)
}

// TODO を更新
func updateTodo(c *gin.Context) {
	var todo Todo
	if err := db.First(&todo, c.Param("id")).Error; err != nil {
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
	if err := db.First(&todo, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "TODO not found"})
		return
	}
	db.Delete(&todo)
	c.JSON(http.StatusOK, gin.H{"message": "TODO deleted"})
}

func main() {
	r := gin.Default()

	// API ルート
	r.GET("/todos", getTodos)
	r.POST("/todos", createTodo)
	r.PUT("/todos/:id", updateTodo)
	r.DELETE("/todos/:id", deleteTodo)
	r.GET("todos/overdue", getOverdueTodos)
	r.GET("todos/has_due_date", getHasDueDateTodos)
	r.Run(":8080") // サーバー起動
}
