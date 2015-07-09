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
	}

	sqlStore.SetClient(client)
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

// TestClient tests saving, loading, and removing client data
func TestClient(t *testing.T) {
	assert := assert.New(t)

	testClient := &osin.DefaultClient{
		Id:          "test",
		Secret:      "secret",
		RedirectUri: "redirect",
	}

	sqlStore.SetClient(testClient)

	retClient, err := sqlStore.GetClient("test")
	assert.Nil(err)

	assert.Equal(retClient.GetId(), "test")
	assert.Equal(retClient.GetSecret(), "secret")
	assert.Equal(retClient.GetRedirectUri(), "redirect")
	assert.Nil(retClient.GetUserData())

	sqlStore.RemoveClient("test")

	_, err = sqlStore.GetClient("test")
	assert.NotNil(err)
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

// compareAccessData compares the returned access data to the setup "test" access data to
// check if the data is being properly saved and loaded
func compareAccessData(accessToken string, retAccessData *osin.AccessData, assert *assert.Assertions) {
	// test if client is properly loaded
	assert.Equal(retAccessData.Client.GetId(), "testclient")
	assert.Equal(retAccessData.Client.GetSecret(), "testsecret")
	assert.Equal(retAccessData.Client.GetRedirectUri(), "testredirect")

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
	assert.Equal(retAccessData.AccessToken, accessToken)
	assert.Equal(retAccessData.RefreshToken, "testrefresh")
	assert.Equal(retAccessData.ExpiresIn, int32(100))
	assert.Equal(retAccessData.Scope, "testscope")
	assert.Equal(retAccessData.RedirectUri, "testredirect")
	if !retAccessData.CreatedAt.Equal(time.Date(2015, 2, 30, 6, 30, 0, 0, time.Local)) {
		assert.Error(errors.New("The created_at dates are not equal"))
	}
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

	compareAccessData("testaccesstoken", retAccessData, assert)

	err = sqlStore.RemoveAuthorize("testcode")
	assert.Nil(err)
	err = sqlStore.RemoveAccess("testaccesstoken")
	assert.Nil(err)
}

// TestAccessNonEmptyPrevToken tests saving, loading, and removing access data with a nonempty AccessData field
func TestAccessNonEmptyPrevToken(t *testing.T) {
	assert := assert.New(t)

	authData := setupAuthData(assert)

	// Set up access data objects so that
	// beforePrevAccessData -> prevAccessData -> accessData
	// if load the access data for accessData we should only get the fields for
	// accessData and prevAccessData not beforePrevAccessData since the AccessData field
	// is only for the previous refresh token and loading the entire access data chain to retrieve
	// one object is inefficient
	// Also if accessData is loaded, prevAccessData's fields for Client and AuthorizeData are not loaded either

	beforePrevAccessData := &osin.AccessData{
		Client:        client,
		AuthorizeData: authData,
		AccessToken:   "testaccesstoken1",
		RefreshToken:  "testrefresh",
		ExpiresIn:     100,
		Scope:         "testscope",
		RedirectUri:   "testredirect",
		CreatedAt:     time.Date(2015, 2, 30, 6, 30, 0, 0, time.Local),
	}

	prevAccessData := &osin.AccessData{
		AccessData:    beforePrevAccessData,
		Client:        client,
		AuthorizeData: authData,
		AccessToken:   "testaccesstoken2",
		RefreshToken:  "testrefresh",
		ExpiresIn:     100,
		Scope:         "testscope",
		RedirectUri:   "testredirect",
		CreatedAt:     time.Date(2015, 2, 30, 6, 30, 0, 0, time.Local),
	}

	accessData := &osin.AccessData{
		AccessData:    prevAccessData,
		Client:        client,
		AuthorizeData: authData,
		AccessToken:   "testaccesstoken3",
		RefreshToken:  "testrefresh",
		ExpiresIn:     100,
		Scope:         "testscope",
		RedirectUri:   "testredirect",
		CreatedAt:     time.Date(2015, 2, 30, 6, 30, 0, 0, time.Local),
	}

	err := sqlStore.SaveAccess(beforePrevAccessData)
	assert.Nil(err)
	err = sqlStore.SaveAccess(prevAccessData)
	assert.Nil(err)
	err = sqlStore.SaveAccess(accessData)
	assert.Nil(err)

	// load the access data for accessData
	retAccessData, err := sqlStore.LoadAccess("testaccesstoken3")
	compareAccessData("testaccesstoken3", retAccessData, assert)

	// Test that foreign keys are not loaded for the previous access data
	assert.Nil(retAccessData.AccessData.AccessData)
	assert.Nil(retAccessData.AccessData.Client)
	assert.Nil(retAccessData.AccessData.AuthorizeData)

	// Test other fields
	assert.Equal(retAccessData.AccessData.AccessToken, "testaccesstoken2")
	assert.Equal(retAccessData.AccessData.RefreshToken, "testrefresh")
	assert.Equal(retAccessData.AccessData.ExpiresIn, int32(100))
	assert.Equal(retAccessData.AccessData.Scope, "testscope")
	assert.Equal(retAccessData.AccessData.RedirectUri, "testredirect")
	if !retAccessData.AccessData.CreatedAt.Equal(time.Date(2015, 2, 30, 6, 30, 0, 0, time.Local)) {
		assert.Error(errors.New("The created_at dates are not equal"))
	}

	err = sqlStore.RemoveAuthorize("testcode")
	assert.Nil(err)
	err = sqlStore.RemoveAccess("testaccesstoken1")
	assert.Nil(err)
	err = sqlStore.RemoveAccess("testaccesstoken2")
	assert.Nil(err)
	err = sqlStore.RemoveAccess("testaccesstoken3")
	assert.Nil(err)
}

// TestRefresh tests loading and removing access data from the refresh token
func TestRefresh(t *testing.T) {
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

	err := sqlStore.SaveAccess(accessData)
	assert.Nil(err)

	retAccessData, err := sqlStore.LoadRefresh("testrefresh")
	assert.Nil(err)

	compareAccessData("testaccesstoken", retAccessData, assert)

	err = sqlStore.RemoveAuthorize("testcode")
	assert.Nil(err)
	err = sqlStore.RemoveRefresh("testrefresh")
	assert.Nil(err)
}
