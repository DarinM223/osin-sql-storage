package gorm_schema

import "time"

/*
 * Contains sample database models for the gorm orm
 * that match the tables needed for SQLStorage
 */

type Client struct {
	ID          string `gorm:"primary_key"`
	Secret      string
	RedirectUri string
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
