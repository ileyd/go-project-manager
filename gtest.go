package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	// mysql driver
	_ "github.com/go-sql-driver/mysql"
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

type Tests struct {
	Company         string `json:"company"`
	Email           string `json:"email"`
	Material        string `json:"material"`
	Process         string `json:"process"`
	Samples         bool   `json"samples"`
	TestFile        bool   `json:"testfile"`
	SamplesRecieved string `json:"SamplesRecieved"`
	Machine         string `json:"machine"`
	RequestedBy     string `json:"RequestedBy"`
	PerformedBy     string `json:"PerformedBy"`
	DueDate         string `json:"DueDate"`
	Completion      string `json:"Completion"`
	Status          string `json:"Status"`
}

type Page struct {
	Tests []Tests `json:"data"`
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("mysql", DATABASE)
	if err != nil {
		log.Println(err)
	}
	defer db.Close()
	rows, err := db.Query("select * from tests")
	if err != nil {
		log.Println(err)
	}
	b := Page{Tests: []Tests{}}
	for rows.Next() {
		res := Tests{}
		rows.Scan(&res.Company, &res.Email, &res.Material, &res.Process, &res.Samples, &res.TestFile, &res.SamplesRecieved, &res.Machine, &res.RequestedBy, &res.PerformedBy, &res.DueDate, &res.Completion, &res.Status)
		b.Tests = append(b.Tests, res)
	}

	err = templates.ExecuteTemplate(w, "index.html", &b)
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
