package sqlstore

import (
	"fmt"
	"github.com/DarinM223/osin-sql-storage/sqlstore/gorm_schema"
	"github.com/RangelReale/osin"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"os"
	"reflect"
	"testing"
	"time"
)

// stores the context variables for the tests
var testingContext = struct {
	DB    gorm.DB
	Store *SQLStorage
}{}

// setupDB creates a test database file and creates the oauth tables before the tests are ran
func setupDB() {
	db, err := gorm.Open("sqlite3", "./test.db")
	if err != nil {
		fmt.Println(err)
	}

	// create tables
	// db.LogMode(true)
	db.AutoMigrate(&gorm_schema.Client{}, &gorm_schema.AuthorizeData{}, &gorm_schema.AccessData{})
	db.Model(&gorm_schema.AccessData{}).AddForeignKey("authorize_data_code", "authorize_data", "CASCADE", "RESTRICT")
	db.Model(&gorm_schema.AccessData{}).AddForeignKey("prev_access_data_token", "access_data", "CASCADE", "RESTRICT")

	testingContext.DB = db
	testingContext.Store = NewSQLStorage(db.DB())
}

// teardownDB closes the database and removes the database file after the tests are ran
func teardownDB() {
	err := testingContext.DB.Close()
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

// List of input tests for Client
var clientTests = []*osin.DefaultClient{
	&osin.DefaultClient{Id: "test", Secret: "secret", RedirectUri: "redirect"},
}

// List of input tests for AuthorizeData
var authDataTests = []osin.AuthorizeData{
	osin.AuthorizeData{Code: "testcode", ExpiresIn: 100, Scope: "testscope", RedirectUri: "testredirect",
		State: "teststate", CreatedAt: time.Date(2015, 2, 30, 6, 30, 0, 0, time.Local)},
}

// List of input tests for AccessData
var accessDataTests = []osin.AccessData{
	osin.AccessData{AccessToken: "testaccesstoken1", RefreshToken: "testrefresh", ExpiresIn: 100,
		Scope: "testscope", RedirectUri: "testredirect", CreatedAt: time.Date(2015, 2, 30, 6, 30, 0, 0, time.Local)},
	osin.AccessData{AccessToken: "testaccesstoken2", RefreshToken: "testrefresh2", ExpiresIn: 100,
		Scope: "testscope", RedirectUri: "testredirect", CreatedAt: time.Date(2015, 2, 30, 6, 30, 0, 0, time.Local)},
	osin.AccessData{AccessToken: "testaccesstoken3", RefreshToken: "testrefresh3", ExpiresIn: 100,
		Scope: "testscope", RedirectUri: "testredirect", CreatedAt: time.Date(2015, 2, 30, 6, 30, 0, 0, time.Local)},
}

func TestRun(t *testing.T) {
	testClient(t)
	testingContext.Store.SetClient(clientTests[0])
	testAuthorize(t, clientTests[0])

	authData := authDataTests[0]
	authData.Client = clientTests[0]
	testingContext.Store.SaveAuthorize(&authData)

	// Test access data from access token parameter
	testAccessData(t, clientTests[0], &authDataTests[0], func(accessData *osin.AccessData) (*osin.AccessData, error) {
		return testingContext.Store.LoadAccess(accessData.AccessToken)
	})
	// Test access data from refresh token parameter
	testAccessData(t, clientTests[0], &authDataTests[0], func(accessData *osin.AccessData) (*osin.AccessData, error) {
		return testingContext.Store.LoadRefresh(accessData.RefreshToken)
	})

	// Test recursive access data from access token parameter
	testAccessDataRecursive(t, clientTests[0], &authDataTests[0], func(accessData *osin.AccessData) (*osin.AccessData, error) {
		return testingContext.Store.LoadAccess(accessData.AccessToken)
	})
	// Test recursive access data from refresh token parameter
	testAccessDataRecursive(t, clientTests[0], &authDataTests[0], func(accessData *osin.AccessData) (*osin.AccessData, error) {
		return testingContext.Store.LoadRefresh(accessData.RefreshToken)
	})

	testingContext.Store.RemoveAuthorize(authDataTests[0].Code)
	testingContext.Store.RemoveClient(clientTests[0].Id)
}

// testClient tests saving, loading, and removing client data
func testClient(t *testing.T) {
	for _, client := range clientTests {
		testingContext.Store.SetClient(client)
		retClient, err := testingContext.Store.GetClient("test")
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(retClient, client) {
			t.Errorf("\"%v\": expected %v", retClient, client)
		}
		testingContext.Store.RemoveClient("test")
		_, err = testingContext.Store.GetClient("test")
		if err == nil {
			t.Error("Error should be thrown")
		}
	}
}

// testAuthorize tests saving, loading, and removing authorization data
func testAuthorize(t *testing.T, client osin.Client) {
	authTests := []*osin.AuthorizeData{}
	// copy auth data tests and set the client
	for _, authData := range authDataTests {
		authDataCopy := authData
		authDataCopy.Client = client
		authTests = append(authTests, &authDataCopy)
	}
	for _, authData := range authTests {
		err := testingContext.Store.SaveAuthorize(authData)
		if err != nil {
			t.Error(err)
		}

		retAuthData, err := testingContext.Store.LoadAuthorize(authData.Code)
		if err != nil {
			t.Error(err)
		}

		if !compareAuthData(retAuthData, authData) {
			t.Errorf("\"%v\": expected %v", retAuthData, authData)
		}

		err = testingContext.Store.RemoveAuthorize(authData.Code)
		if err != nil {
			t.Error(err)
		}
	}
}

type loadAccessDataFunc func(*osin.AccessData) (*osin.AccessData, error)

// testAccessData tests saving, loading, and removing access data with an empty AccessData field
func testAccessData(t *testing.T, client osin.Client, authData *osin.AuthorizeData, getDataFunc loadAccessDataFunc) {
	accessTests := []*osin.AccessData{}
	// copy access data tests and set the client and auth data
	for _, accessData := range accessDataTests {
		accessDataCopy := accessData
		accessDataCopy.Client = client
		accessDataCopy.AuthorizeData = authData
		accessTests = append(accessTests, &accessDataCopy)
	}
	for _, accessData := range accessTests {
		err := testingContext.Store.SaveAccess(accessData)
		if err != nil {
			t.Error(err)
		}

		retAccessData, err := getDataFunc(accessData)
		if err != nil {
			t.Error(err)
		}

		// Compare the access data's client fields
		if !reflect.DeepEqual(retAccessData.Client, accessData.Client) {
			t.Errorf("\"%v\": expected %v", retAccessData.Client, accessData.Client)
		}

		// Compare the access data's auth data fields
		if !compareAuthData(retAccessData.AuthorizeData, accessData.AuthorizeData) {
			t.Errorf("\"%v\": expected %v", retAccessData.AuthorizeData, accessData.AuthorizeData)
		}

		// Compare the access data's other fields
		if !compareAccessData(retAccessData, accessData) {
			t.Errorf("\"%v\": expected %v", retAccessData, accessData)
		}

		err = testingContext.Store.RemoveAccess(accessData.AccessToken)
		if err != nil {
			t.Error(err)
		}
	}
}

// testAccessDataRecursive tests saving, loading, and removing access data with a nonempty AccessData field
func testAccessDataRecursive(t *testing.T, client osin.Client, authData *osin.AuthorizeData, getDataFunc loadAccessDataFunc) {
	accessTests := []*osin.AccessData{}

	// store the previous access data so you can create a linked list
	var prevAccessData *osin.AccessData

	// copy access data tests and set the client and auth data
	for _, accessData := range accessDataTests {
		accessDataCopy := accessData
		accessDataCopy.Client = client
		accessDataCopy.AuthorizeData = authData

		accessDataCopy.AccessData = prevAccessData

		accessTests = append(accessTests, &accessDataCopy)
		prevAccessData = accessTests[len(accessTests)-1]
	}
	for index, accessData := range accessTests {
		err := testingContext.Store.SaveAccess(accessData)
		if err != nil {
			t.Error(err)
		}

		retAccessData, err := getDataFunc(accessData)
		if err != nil {
			t.Error(err)
		}

		// Compare the access data's client fields
		if !reflect.DeepEqual(retAccessData.Client, accessData.Client) {
			t.Errorf("\"%v\": expected %v", retAccessData.Client, accessData.Client)
		}

		// Compare the access data's auth data fields
		if !compareAuthData(retAccessData.AuthorizeData, accessData.AuthorizeData) {
			t.Errorf("\"%v\": expected %v", retAccessData.AuthorizeData, accessData.AuthorizeData)
		}

		// Compare the access data's other fields
		if !compareAccessData(retAccessData, accessData) {
			t.Errorf("\"%v\": expected %v", retAccessData, accessData)
		}

		if index == 0 {
			if retAccessData.AccessData != nil {
				t.Errorf("Access Data's access data for the first element should be nil")
			}
		} else {
			if retAccessData.AccessData.Client != nil {
				t.Errorf("Access Data's access data's Client is not nil")
			}
			if retAccessData.AccessData.AuthorizeData != nil {
				t.Errorf("Access Data's access data's AuthorizeData is not nil")
			}
			if retAccessData.AccessData.AccessData != nil {
				t.Errorf("Access Data's access data's AccessData is not nil")
			}
			if !compareAccessData(retAccessData.AccessData, accessData.AccessData) {
				t.Errorf("\"%v\": expected %v", retAccessData.AccessData, accessData.AccessData)
			}
		}
	}
	// Delete all of the access tokens after
	for _, accessData := range accessTests {
		err := testingContext.Store.RemoveAccess(accessData.AccessToken)
		if err != nil {
			t.Error(err)
		}
	}
}

// BenchmarkClient benchmarks saving, loading, and removing client data records
func BenchmarkClient(b *testing.B) {
	for n := 0; n < b.N; n++ {
		err := testingContext.Store.SetClient(clientTests[0])
		if err != nil {
			b.Error(err)
		}

		_, err = testingContext.Store.GetClient(clientTests[0].GetId())
		if err != nil {
			b.Error(err)
		}

		testingContext.Store.RemoveClient(clientTests[0].GetId())
	}
}

// BenchmarkAuthorize benchmarks saving, loading, and removing authorize data records
func BenchmarkAuthorize(b *testing.B) {
	testingContext.Store.SetClient(clientTests[0])

	authDataCopy := authDataTests[0]
	authDataCopy.Client = clientTests[0]

	for n := 0; n < b.N; n++ {
		err := testingContext.Store.SaveAuthorize(&authDataCopy)
		if err != nil {
			b.Error(err)
		}

		_, err = testingContext.Store.LoadAuthorize(authDataCopy.Code)
		if err != nil {
			b.Error(err)
		}

		testingContext.Store.RemoveAuthorize(authDataCopy.Code)
	}

	testingContext.Store.RemoveClient(clientTests[0].GetId())
}

// BenchmarkAccess benchmarks saving, loading, and removing access data records
func BenchmarkAccess(b *testing.B) {
	testingContext.Store.SetClient(clientTests[0])
	authData := authDataTests[0]
	authData.Client = clientTests[0]
	testingContext.Store.SaveAuthorize(&authData)

	accessDataCopy := accessDataTests[0]
	accessDataCopy.AuthorizeData = &authData
	accessDataCopy.Client = clientTests[0]

	for n := 0; n < b.N; n++ {
		err := testingContext.Store.SaveAccess(&accessDataCopy)
		if err != nil {
			b.Error(err)
		}

		_, err = testingContext.Store.LoadAccess(accessDataCopy.AccessToken)
		if err != nil {
			b.Error(err)
		}

		testingContext.Store.RemoveAccess(accessDataCopy.AccessToken)
	}
}

func compareAuthData(authData1, authData2 *osin.AuthorizeData) bool {
	// testAuthDataType is a struct for comparing AuthorizeData structs without the
	// createdAt and client fields
	type testAuthDataType struct {
		Code        string
		ExpiresIn   int32
		Scope       string
		RedirectUri string
		State       string
	}

	testAuthData1 := testAuthDataType{
		Code:        authData1.Code,
		ExpiresIn:   authData1.ExpiresIn,
		Scope:       authData1.Scope,
		RedirectUri: authData1.RedirectUri,
		State:       authData1.State,
	}

	testAuthData2 := testAuthDataType{
		Code:        authData2.Code,
		ExpiresIn:   authData2.ExpiresIn,
		Scope:       authData2.Scope,
		RedirectUri: authData2.RedirectUri,
		State:       authData2.State,
	}

	// Compare the createdAt fields, and the Client fields, and the other fields in AuthorizeData
	if !reflect.DeepEqual(testAuthData1, testAuthData2) {
		return false
	}
	return authData1.CreatedAt.Equal(authData2.CreatedAt)
}

// compareAccessData compares the returned access data to the setup "test" access data to
// check if the data is being properly saved and loaded
func compareAccessData(accessData1, accessData2 *osin.AccessData) bool {
	type testAccessDataType struct {
		AccessToken  string
		RefreshToken string
		ExpiresIn    int32
		Scope        string
		RedirectUri  string
	}

	testAccessData1 := testAccessDataType{
		AccessToken:  accessData1.AccessToken,
		RefreshToken: accessData1.RefreshToken,
		ExpiresIn:    accessData1.ExpiresIn,
		Scope:        accessData1.Scope,
		RedirectUri:  accessData1.RedirectUri,
	}

	testAccessData2 := testAccessDataType{
		AccessToken:  accessData2.AccessToken,
		RefreshToken: accessData2.RefreshToken,
		ExpiresIn:    accessData2.ExpiresIn,
		Scope:        accessData2.Scope,
		RedirectUri:  accessData2.RedirectUri,
	}

	if !reflect.DeepEqual(testAccessData1, testAccessData2) {
		return false
	}
	return accessData1.CreatedAt.Equal(accessData2.CreatedAt)
}
