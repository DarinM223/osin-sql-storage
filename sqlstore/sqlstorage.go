package sqlstore

import (
	"database/sql"
	"errors"
	"github.com/RangelReale/osin"
)

// The database that stores the oauth2 data has to have the following schema:
// clients:
//   id           string
//   secret       string
//   redirect_uri string

type SQLStorage struct {
	authDB *sql.DB
}

func NewSQLStorage(authDB *sql.DB) *SQLStorage {
	return &SQLStorage{
		authDB: authDB,
	}
}

func (store *SQLStorage) GetClient(id string) (osin.Client, error) {
	var (
		clientID    string
		secret      string
		redirectURI string
	)

	rows, err := store.authDB.Query("SELECT * FROM clients WHERE id = ?", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		err := rows.Scan(&clientID, &secret, &redirectURI)
		if err != nil {
			return nil, err
		}

		return &osin.DefaultClient{
			Id:          clientID,
			Secret:      secret,
			RedirectUri: redirectURI,
		}, nil
	}

	return nil, errors.New("There are no clients with that client id")
}

func (store *SQLStorage) SaveAuthorize(authorizeData *osin.AuthorizeData) error {
	return errors.New("Implement this")
}

func (store *SQLStorage) LoadAuthorize(authorizeData *osin.AuthorizeData) (*osin.AuthorizeData, error) {
	return nil, errors.New("Implement this")
}

func (store *SQLStorage) RemoveAuthorize(code string) error {
	return errors.New("Implement this")
}

func (store *SQLStorage) SaveAccess(accessData *osin.AccessData) error {
	return errors.New("Implement this")
}

func (store *SQLStorage) LoadAccess(token string) (*osin.AccessData, error) {
	return nil, errors.New("Implement this")
}

func (store *SQLStorage) RemoveAccess(token string) error {
	return errors.New("Implement this")
}

func LoadRefresh(token string) (*osin.AccessData, error) {
	return nil, errors.New("Implement this")
}

func RemoveRefresh(token string) error {
	return errors.New("Implement this")
}
