package main

// Use github.com/RangelReale/osincli client to test
// Open url in browser:
// http://localhost:14001

import (
	"fmt"
	"github.com/DarinM223/osin-sql-storage/sqlstore"
	"github.com/DarinM223/osin-sql-storage/sqlstore/gorm_schema"
	"github.com/RangelReale/osin"
	"github.com/RangelReale/osin/example"
	"github.com/RangelReale/osincli"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"net/http"
)

func main() {
	// create http muxes
	serverhttp := http.NewServeMux()
	clienthttp := http.NewServeMux()

	// create server
	config := osin.NewServerConfig()

	db, err := gorm.Open("sqlite3", "./test.db")
	if err != nil {
		fmt.Println(err)
	}
	defer db.Close()

	db.AutoMigrate(&gorm_schema.Client{}, &gorm_schema.AuthorizeData{}, &gorm_schema.AccessData{})
	db.Model(&gorm_schema.AccessData{}).AddForeignKey("authorize_data_code", "authorize_data", "CASCADE", "RESTRICT")
	db.Model(&gorm_schema.AccessData{}).AddForeignKey("prev_access_data_token", "access_data", "CASCADE", "RESTRICT")

	sstorage := sqlstore.NewSQLStorage(db.DB())

	sstorage.SetClient(&osin.DefaultClient{
		Id:          "1234",
		Secret:      "aabbccdd",
		RedirectUri: "http://localhost:14001/appauth",
	})
	server := osin.NewServer(config, sstorage)

	// create client
	cliconfig := &osincli.ClientConfig{
		ClientId:     "1234",
		ClientSecret: "aabbccdd",
		AuthorizeUrl: "http://localhost:14000/authorize",
		TokenUrl:     "http://localhost:14000/token",
		RedirectUrl:  "http://localhost:14001/appauth",
	}
	client, err := osincli.NewClient(cliconfig)
	if err != nil {
		panic(err)
	}

	// create a new request to generate the url
	areq := client.NewAuthorizeRequest(osincli.CODE)

	// SERVER

	// Authorization code endpoint
	serverhttp.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
			if !example.HandleLoginPage(ar, w, r) {
				return
			}
			ar.Authorized = true
			server.FinishAuthorizeRequest(resp, r, ar)
		}
		if resp.IsError && resp.InternalError != nil {
			fmt.Printf("ERROR: %s\n", resp.InternalError)
		}
		osin.OutputJSON(resp, w, r)
	})

	// Access token endpoint
	serverhttp.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAccessRequest(resp, r); ar != nil {
			ar.Authorized = true
			server.FinishAccessRequest(resp, r, ar)
		}
		if resp.IsError && resp.InternalError != nil {
			fmt.Printf("ERROR: %s\n", resp.InternalError)
		}
		osin.OutputJSON(resp, w, r)
	})

	// Information endpoint
	serverhttp.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ir := server.HandleInfoRequest(resp, r); ir != nil {
			server.FinishInfoRequest(resp, r, ir)
		}
		osin.OutputJSON(resp, w, r)
	})

	// CLIENT

	// Home
	clienthttp.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		u := areq.GetAuthorizeUrl()

		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Login</a>", u.String())))
	})

	// Auth endpoint
	clienthttp.HandleFunc("/appauth", func(w http.ResponseWriter, r *http.Request) {
		// parse a token request
		areqdata, err := areq.HandleRequest(r)
		if err != nil {
			w.Write([]byte(fmt.Sprintf("ERROR: %s\n", err)))
			return
		}

		treq := client.NewAccessRequest(osincli.AUTHORIZATION_CODE, areqdata)

		// show access request url (for debugging only)
		u2 := treq.GetTokenUrl()
		w.Write([]byte(fmt.Sprintf("Access token URL: %s\n", u2.String())))

		// exchange the authorize token for the access token
		ad, err := treq.GetToken()
		if err != nil {
			w.Write([]byte(fmt.Sprintf("ERROR: %s\n", err)))
			return
		}
		w.Write([]byte(fmt.Sprintf("Access token: %+v\n", ad)))
	})

	go http.ListenAndServe(":14001", clienthttp)
	http.ListenAndServe(":14000", serverhttp)
}
