package main

import (
	"database/sql"
	"fmt"
	"html"
	"html/template"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"

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
	NAME = "tests"
	// DATABASE connection String
	DATABASE = USERNAME + ":" + PASS + "@/" + NAME + "?charset=utf8"
)

var templates = template.Must(template.ParseFiles("templates/index.html", "templates/orders.html", "templates/login.html", "templates/modify.html", "templates/register.html", "templates/new.html"))

type Tests struct {
	ID              string `json:"id"`
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

func ordersHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("mysql", DATABASE)
	if err != nil {
		log.Println(err)
	}
	defer db.Close()
	rows, err := db.Query("select id, company, email, material, process, samples, testfile, samples , machine, requestedby, performedby, duedate, completion, status from tests")
	if err != nil {
		log.Println(err)
	}
	b := Page{Tests: []Tests{}}
	for rows.Next() {
		res := Tests{}
		rows.Scan(&res.ID, &res.Company, &res.Email, &res.Material, &res.Process, &res.Samples, &res.TestFile, &res.SamplesRecieved, &res.Machine, &res.RequestedBy, &res.PerformedBy, &res.DueDate, &res.Completion, &res.Status)
		b.Tests = append(b.Tests, res)
	}

	err = templates.ExecuteTemplate(w, "orders.html", &b)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func newHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		err := templates.ExecuteTemplate(w, "new.html", "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case "POST":
		company := r.FormValue("company")
		email := r.FormValue("email")
		material := r.FormValue("material")
		process := r.FormValue("process")
		samples := r.FormValue("samples")
		testfile := r.FormValue("files")
		machine := r.FormValue("machine")
		requestedby := r.FormValue("requestedby")
		duedate := r.FormValue("duedate")
		fmt.Println(company, email, material, process, samples, testfile, machine, requestedby, duedate)
		db, err := sql.Open("mysql", DATABASE)
		if err != nil {
			log.Println(err)
		}
		defer db.Close()
	}
}

func delHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("mysql", DATABASE)
	if err != nil {
		log.Println(err)
	}
	defer db.Close()
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		err := templates.ExecuteTemplate(w, "login.html", "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case "POST":
		email := r.FormValue("email")
		password := r.FormValue("password")
		db, err := sql.Open("mysql", DATABASE)
		if err != nil {
			log.Println(err)
		}
		defer db.Close()
		var hashedPassword string
		err = db.QueryRow("select password from users where email=?", html.EscapeString(email)).Scan(&hashedPassword)
		if err == sql.ErrNoRows {
			http.Redirect(w, r, "/register", 303)
		}
		if err != nil {
			log.Println(err)

		}
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			log.Println(err)

		}

	}

}
func registerHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		err := templates.ExecuteTemplate(w, "register.html", "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case "POST":
		email := r.FormValue("email")
		password := r.FormValue("password")
		db, err := sql.Open("mysql", DATABASE)
		if err != nil {
			log.Println(err)
		}
		defer db.Close()
		smt, err := db.Prepare("insert into user(email, password) values(?. ?)")
		if err != nil {
			log.Println(err)
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Println(err)
		}
		_, err = smt.Exec(html.EscapeString(email), hashedPassword)
		if err != nil {
			log.Println(err)
		}

	}

}
func putHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("mysql", DATABASE)
	if err != nil {
		log.Println(err)
	}
	defer db.Close()
}
func rootHandler(w http.ResponseWriter, r *http.Request) {
	err := templates.ExecuteTemplate(w, "index.html", "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

}
func statusUpdateHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("mysql", DATABASE)
	if err != nil {
		log.Println(err)
	}
	defer db.Close()
}

func main() {

	router := mux.NewRouter()
	router.HandleFunc("/new", newHandler)
	router.HandleFunc("/del/{id}", delHandler)
	router.HandleFunc("/put/{id}", putHandler)
	router.HandleFunc("/login", loginHandler)
	router.HandleFunc("/register", registerHandler)
	router.HandleFunc("/orders", ordersHandler)
	router.HandleFunc("/", rootHandler)
	err := http.ListenAndServe(PORT, router)
	if err != nil {
		log.Fatal(err)

	}
}
