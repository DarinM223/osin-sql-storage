package sqlstore

import (
	"errors"
	"fmt"
	"github.com/RangelReale/osin"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"
)

var db gorm.DB
var sqlStore *SQLStorage

var client osin.Client

// setupDB creates a test database file and creates the oauth tables
func setupDB() {
	var err error
	db, err = gorm.Open("sqlite3", "./test.db")
	if err != nil {
		fmt.Println(err)
	}

	// create tables
	// db.LogMode(true)
	db.AutoMigrate(&Client{}, &AuthorizeData{}, &AccessData{})
	db.Model(&AccessData{}).AddForeignKey("authorize_data_code", "authorize_data", "CASCADE", "RESTRICT")
	db.Model(&AccessData{}).AddForeignKey("prev_access_data_token", "access_data", "CASCADE", "RESTRICT")

	sqlStore = NewSQLStorage(db.DB())

	client = &osin.DefaultClient{
		Id:          "testclient",
		Secret:      "testsecret",
		RedirectUri: "testredirect",
		UserData:    "testuserid",
	}

	dbClient := &Client{
		ID:          client.GetId(),
		Secret:      client.GetSecret(),
		RedirectUri: client.GetRedirectUri(),
		UserID:      client.GetUserData().(string),
	}

	db.Create(dbClient)
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

func setupAuthData(assert *assert.Assertions) *osin.AuthorizeData {
	authData := &osin.AuthorizeData{
		Code:        "testcode",
		ExpiresIn:   100,
		Scope:       "testscope",
		RedirectUri: "testredirect",
		State:       "teststate",
		CreatedAt:   time.Date(2015, 2, 30, 6, 30, 0, 0, time.Local),
		Client:      client,
	}
	err := sqlStore.SaveAuthorize(authData)
	assert.Nil(err)
	return authData
}

// TestAuthorize tests saving, loading, and removing authorization data
func TestAuthorize(t *testing.T) {
	assert := assert.New(t)

	setupAuthData(assert)

	retAuthData, err := sqlStore.LoadAuthorize("testcode")
	assert.Nil(err)

	// test if client is properly loaded
	assert.Equal(retAuthData.Client.GetId(), "testclient")
	assert.Equal(retAuthData.Client.GetSecret(), "testsecret")
	assert.Equal(retAuthData.Client.GetRedirectUri(), "testredirect")
	assert.Equal(retAuthData.Client.GetUserData().(string), "testuserid")

	// test other fields
	assert.Equal(retAuthData.Code, "testcode")
	assert.Equal(retAuthData.ExpiresIn, int32(100))
	assert.Equal(retAuthData.Scope, "testscope")
	assert.Equal(retAuthData.RedirectUri, "testredirect")
	assert.Equal(retAuthData.State, "teststate")
	if !retAuthData.CreatedAt.Equal(time.Date(2015, 2, 30, 6, 30, 0, 0, time.Local)) {
		assert.Error(errors.New("The created_at dates are not equal"))
	}

	err = sqlStore.RemoveAuthorize("testcode")
	assert.Nil(err)
}

// TestAccessEmptyPrevToken tests saving, loading, and removing access data with an empty AccessData field
func TestAccessEmptyPrevToken(t *testing.T) {
	assert := assert.New(t)

	authData := setupAuthData(assert)

	accessData := &osin.AccessData{
		Client:        client,
		AuthorizeData: authData,
		AccessToken:   "testaccesstoken",
		RefreshToken:  "testrefresh",
		ExpiresIn:     100,
		Scope:         "testscope",
		RedirectUri:   "testredirect",
		CreatedAt:     time.Date(2015, 2, 30, 6, 30, 0, 0, time.Local),
	}

	sqlStore.SaveAccess(accessData)

	retAccessData, err := sqlStore.LoadAccess("testaccesstoken")
	assert.Nil(err)

	// test if client is properly loaded
	assert.Equal(retAccessData.Client.GetId(), "testclient")
	assert.Equal(retAccessData.Client.GetSecret(), "testsecret")
	assert.Equal(retAccessData.Client.GetRedirectUri(), "testredirect")
	assert.Equal(retAccessData.Client.GetUserData().(string), "testuserid")

	// test if auth data is properly loaded
	assert.Equal(retAccessData.AuthorizeData.Code, "testcode")
	assert.Equal(retAccessData.AuthorizeData.ExpiresIn, int32(100))
	assert.Equal(retAccessData.AuthorizeData.Scope, "testscope")
	assert.Equal(retAccessData.AuthorizeData.RedirectUri, "testredirect")
	assert.Equal(retAccessData.AuthorizeData.State, "teststate")
	if !retAccessData.AuthorizeData.CreatedAt.Equal(time.Date(2015, 2, 30, 6, 30, 0, 0, time.Local)) {
		assert.Error(errors.New("The created_at dates are not equal"))
	}

	// test other fields
	assert.Equal(retAccessData.AccessToken, "testaccesstoken")
	assert.Equal(retAccessData.RefreshToken, "testrefresh")
	assert.Equal(retAccessData.ExpiresIn, int32(100))
	assert.Equal(retAccessData.Scope, "testscope")
	assert.Equal(retAccessData.RedirectUri, "testredirect")
	if !retAccessData.CreatedAt.Equal(time.Date(2015, 2, 30, 6, 30, 0, 0, time.Local)) {
		assert.Error(errors.New("The created_at dates are not equal"))
	}

	err = sqlStore.RemoveAuthorize("testcode")
	assert.Nil(err)
}

func TestAccessNonEmptyPrevToken(t *testing.T) {
	// TODO: implement this
}

// TestRefresh tests loading and removing access data from the refresh token
func TestRefresh(t *testing.T) {
	// TODO: implement this
}
