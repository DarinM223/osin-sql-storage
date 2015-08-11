package sqlstore

import (
	"database/sql"
	"encoding/json"
	"github.com/RangelReale/osin"
	_ "github.com/jinzhu/gorm"
	_ "github.com/stretchr/testify/assert"
	"time"
)

/*
 * The database that stores the oauth2 data has to have the following schema:
 * clients:
 * id           string (primary key)
 * secret       string
 * redirect_uri string
 * user_data    string
 *
 * authorize_data:
 * code         string (primary key)
 * expires_in   int32
 * scope        string
 * redirect_uri string
 * state        string
 * created_at   time.Time
 * user_data    string
 * client_id    string (foreign key)
 *
 * access_data:
 * access_token           string (primary key)
 * refresh_token          string (unique)
 * expires_in             int32
 * scope                  string
 * redirect_uri           string
 * created_at             time.Time
 * user_data              string
 * authorize_data_code    string (foreign key)
 * prev_access_data_token string (foreign key)
 * client_id              string (foreign key)
 */

type SQLStorage struct {
	authDB *sql.DB
}

func NewSQLStorage(authDB *sql.DB) *SQLStorage {
	return &SQLStorage{
		authDB: authDB,
	}
}

func (store *SQLStorage) Clone() osin.Storage {
	return store
}

func (store *SQLStorage) Close() {
}

func getUserData(userData string) (interface{}, error) {
	// Return nil if there is no user data
	if userData == "" {
		return nil, nil
	}

	var data interface{}

	err := json.Unmarshal([]byte(userData), &data)
	return data, err
}

func setUserData(userData interface{}) (string, error) {
	// Return empty string if user data is nil
	if userData == nil {
		return "", nil
	}

	data, err := json.Marshal(userData)
	if err != nil {
		return "", err
	}

	userDataStr := string(data)
	return userDataStr, err
}

func (store *SQLStorage) GetClient(id string) (osin.Client, error) {
	var (
		clientID    string
		secret      string
		redirectURI string
		userDataStr string
	)

	row := store.authDB.QueryRow("SELECT * FROM clients WHERE id = ?", id)

	err := row.Scan(&clientID, &secret, &redirectURI, &userDataStr)
	if err != nil {
		return nil, err
	}

	// Unmarshal user data from string
	userData, err := getUserData(userDataStr)
	if err != nil {
		return nil, err
	}

	return &osin.DefaultClient{
		Id:          clientID,
		Secret:      secret,
		RedirectUri: redirectURI,
		UserData:    userData,
	}, nil
}

func (store *SQLStorage) SetClient(client osin.Client) error {
	stmt, err := store.authDB.Prepare("INSERT INTO clients(id, secret, redirect_uri, user_data) VALUES(?, ?, ?, ?)")

	// Marshal user data into string
	userDataStr, err := setUserData(client.GetUserData())
	if err != nil {
		return err
	}

	_, err = stmt.Exec(client.GetId(), client.GetSecret(), client.GetRedirectUri(), userDataStr)
	return err
}

func (store *SQLStorage) RemoveClient(id string) error {
	stmt, err := store.authDB.Prepare("DELETE FROM clients WHERE id = ?")
	if err != nil {
		return err
	}

	_, err = stmt.Exec(id)
	return err
}

func (store *SQLStorage) SaveAuthorize(authorizeData *osin.AuthorizeData) error {
	stmt, err := store.authDB.Prepare(`
		INSERT INTO authorize_data(code, expires_in, scope, redirect_uri, state, created_at, user_data, client_id) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`)
	if err != nil {
		return err
	}

	// Marshal user data into string
	userDataStr, err := setUserData(authorizeData.UserData)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(authorizeData.Code, authorizeData.ExpiresIn, authorizeData.Scope,
		authorizeData.RedirectUri, authorizeData.State, authorizeData.CreatedAt,
		userDataStr, authorizeData.Client.GetId())
	return err
}

func (store *SQLStorage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	var (
		authCode    string
		expiresIn   int32
		scope       string
		redirectURI string
		state       string
		createdAt   time.Time
		userDataStr string
		clientID    string
	)

	row := store.authDB.QueryRow("SELECT * FROM authorize_data WHERE code = ?", code)

	err := row.Scan(&authCode, &expiresIn, &scope, &redirectURI, &state, &createdAt, &userDataStr, &clientID)
	if err != nil {
		return nil, err
	}

	// Unmarshal the user data from string
	userData, err := getUserData(userDataStr)
	if err != nil {
		return nil, err
	}

	// Retrieve the client from the client id
	client, err := store.GetClient(clientID)
	if err != nil {
		return nil, err
	}

	authData := &osin.AuthorizeData{
		Code:        authCode,
		ExpiresIn:   expiresIn,
		Scope:       scope,
		RedirectUri: redirectURI,
		State:       state,
		CreatedAt:   createdAt,
		UserData:    userData,
		Client:      client,
	}

	return authData, nil
}

func (store *SQLStorage) RemoveAuthorize(code string) error {
	stmt, err := store.authDB.Prepare("DELETE FROM authorize_data WHERE code = ?")
	if err != nil {
		return err
	}

	_, err = stmt.Exec(code)
	return err
}

func (store *SQLStorage) SaveAccess(accessData *osin.AccessData) error {
	stmt, err := store.authDB.Prepare(`
		INSERT INTO access_data(access_token, refresh_token,
		expires_in, scope, redirect_uri, created_at, user_data, authorize_data_code, prev_access_data_token, client_id)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`)
	if err != nil {
		return err
	}

	// Marshal user data into string
	userDataStr, err := setUserData(accessData.UserData)
	if err != nil {
		return err
	}

	prevAccessDataToken := ""
	if accessData.AccessData != nil {
		prevAccessDataToken = accessData.AccessData.AccessToken
	}

	authDataCode := ""
	if accessData.AuthorizeData != nil {
		authDataCode = accessData.AuthorizeData.Code
	}

	_, err = stmt.Exec(accessData.AccessToken, accessData.RefreshToken, accessData.ExpiresIn,
		accessData.Scope, accessData.RedirectUri, accessData.CreatedAt, userDataStr, authDataCode,
		prevAccessDataToken, accessData.Client.GetId())
	return err
}

// loadAccess loads all of the access data except for the foreign key data
// (to avoid loading the entire chain of access data)
func (store *SQLStorage) loadAccess(token string, isRefresh ...bool) (*osin.AccessData, string, string, string, error) {
	var (
		accessToken         string
		refreshToken        string
		expiresIn           int32
		scope               string
		redirectURI         string
		createdAt           time.Time
		userDataStr         string
		authorizeDataCode   string
		prevAccessDataToken string
		clientID            string
	)

	var rows *sql.Rows
	var err error
	if len(isRefresh) > 0 && isRefresh[0] == true {
		rows, err = store.authDB.Query("SELECT * FROM access_data WHERE refresh_token = ?", token)
	} else {
		rows, err = store.authDB.Query("SELECT * FROM access_data WHERE access_token = ?", token)
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&accessToken, &refreshToken,
			&expiresIn, &scope, &redirectURI, &createdAt, &userDataStr,
			&authorizeDataCode, &prevAccessDataToken, &clientID)
		if err != nil {
			return nil, "", "", "", err
		}
		break
	}

	// Unmarshal user data from string
	userData, err := getUserData(userDataStr)
	if err != nil {
		return nil, "", "", "", err
	}

	return &osin.AccessData{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
		Scope:        scope,
		RedirectUri:  redirectURI,
		UserData:     userData,
		CreatedAt:    createdAt,
	}, authorizeDataCode, prevAccessDataToken, clientID, err
}

func (store *SQLStorage) LoadAccess(token string) (*osin.AccessData, error) {
	accessData, authDataCode, prevAccessDataToken, clientID, err := store.loadAccess(token)
	// load previous access data if the token is not empty
	var prevAccessData *osin.AccessData
	if prevAccessDataToken != "" {
		prevAccessData, _, _, _, err = store.loadAccess(prevAccessDataToken)
		if err != nil {
			return nil, err
		}
	}
	// load client data
	client, err := store.GetClient(clientID)
	if err != nil {
		return nil, err
	}
	// load authorize data
	authData, err := store.LoadAuthorize(authDataCode)

	accessData.Client = client
	accessData.AuthorizeData = authData
	accessData.AccessData = prevAccessData
	return accessData, err
}

func (store *SQLStorage) RemoveAccess(token string) error {
	stmt, err := store.authDB.Prepare("DELETE FROM access_data WHERE access_token = ?")
	if err != nil {
		return err
	}

	_, err = stmt.Exec(token)
	return err
}

func (store *SQLStorage) LoadRefresh(token string) (*osin.AccessData, error) {
	accessData, authDataCode, prevAccessDataToken, clientID, err := store.loadAccess(token, true)
	// load previous access data if the token is not empty
	var prevAccessData *osin.AccessData
	if prevAccessDataToken != "" {
		prevAccessData, _, _, _, err = store.loadAccess(prevAccessDataToken)
		if err != nil {
			return nil, err
		}
	}
	// load client data
	client, err := store.GetClient(clientID)
	if err != nil {
		return nil, err
	}
	// load authorize data
	authData, err := store.LoadAuthorize(authDataCode)

	accessData.Client = client
	accessData.AuthorizeData = authData
	accessData.AccessData = prevAccessData
	return accessData, err
}

func (store *SQLStorage) RemoveRefresh(token string) error {
	stmt, err := store.authDB.Prepare("DELETE FROM access_data WHERE refresh_token = ?")
	if err != nil {
		return err
	}

	_, err = stmt.Exec(token)
	return err
}
