package sqlstore

import (
	"fmt"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"os"
	"testing"
	"time"
)

type Client struct {
	ID          int `gorm:"primary_key"`
	Secret      string
	RedirectUri string
	UserID      string
}

func (c Client) TableName() string {
	return "clients"
}

type AuthorizeData struct {
	Code        string `gorm:"primary_key"`
	ExpiresIn   int32
	Scope       string
	RedirectUri string
	State       string
	CreatedAt   time.Time
	ClientID    string `sql:"index"`
}

func (a AuthorizeData) TableName() string {
	return "authorize_data"
}

type AccessData struct {
	AccessToken         string `gorm:"primary_key"`
	RefreshToken        string
	ExpiresIn           int32
	Scope               string
	RedirectUri         string
	CreatedAt           time.Time
	AuthorizeDataCode   string `sql:"index"`
	PrevAccessDataToken string `sql:"index"`
	ClientID            string `sql:"index"`
}

func (a AccessData) TableName() string {
	return "access_data"
}

var db gorm.DB

// setupDB creates a test database file and creates the oauth tables
func setupDB() {
	var err error
	db, err = gorm.Open("sqlite3", "./test.db")
	if err != nil {
		fmt.Println(err)
	}

	// create tables
	db.LogMode(true)
	db.AutoMigrate(&Client{}, &AuthorizeData{}, &AccessData{})
	db.Model(&AccessData{}).AddForeignKey("authorize_data_code", "authorize_data", "CASCADE", "RESTRICT")
	db.Model(&AccessData{}).AddForeignKey("prev_access_data_token", "access_data", "CASCADE", "RESTRICT")
}

// teardownDB closes the database and removes the database file
func teardownDB() {
	err := db.Close()
	if err != nil {
		fmt.Println(err)
		return
	}

	err = os.Remove("./test.db")
	if err != nil {
		fmt.Println(err)
		return
	}
}

func TestMain(m *testing.M) {
	setupDB()

	retCode := m.Run()

	teardownDB()

	os.Exit(retCode)
}

// TestAuthorize tests saving, loading, and removing authorization data
func TestAuthorize(t *testing.T) {
	// TODO: create sample authorize data
}

// TestAccess tests saving, loading, and removing access data
func TestAccess(t *testing.T) {
}

// TestRefresh tests loading and removing access data from the refresh token
func TestRefresh(t *testing.T) {
}
