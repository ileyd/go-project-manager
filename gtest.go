package main

import (
	"html/template"
	"log"
	"net/http"
	//	"database/sql"

	"github.com/gorilla/mux"
	// mysql driver
	//	_ "github.com/go-sql-driver/mysql"
)

const (
	// ADDRESS that tracker will return links for
	ADDRESS = "http://localhost:9900"
	// PORT that tracker will listen on
	PORT = ":9900"
	// USERNAME for database
	USERNAME = ""
	// PASS database password
	PASS = ""
	// NAME database name
	NAME = ""
	// DATABASE connection String
	DATABASE = USERNAME + ":" + PASS + "@/" + NAME + "?charset=utf8"
)

var templates = template.Must(template.ParseFiles("assets/paste.html", "assets/index.html", "assets/clone.html"))

func rootHandler(w http.ResponseWriter, r *http.Request) {
	err := templates.Execute(w, "index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {

	router := mux.NewRouter()
	router.HandleFunc("/", rootHandler)
	err := http.ListenAndServe(PORT, router)
	if err != nil {
		log.Fatal(err)

	}
}
