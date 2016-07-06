package main

import (
	"database/sql"
	"html"
	"html/template"
	"io"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
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
var cookieHandler = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32),
)

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
	res := Tests{}
	for rows.Next() {
		rows.Scan(&res.ID, &res.Company, &res.Email, &res.Material, &res.Process, &res.Samples, &res.TestFile, &res.SamplesRecieved, &res.Machine, &res.RequestedBy, &res.PerformedBy, &res.DueDate, &res.Completion, &res.Status)
	}

	err = templates.ExecuteTemplate(w, "orders.html", &res)
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
		db, err := sql.Open("mysql", DATABASE)
		if err != nil {
			log.Println(err)
		}
		defer db.Close()
		smt, err := db.Prepare("insert into tests(company, email, material, process, samples, testfile, machine, requestedby, duedate) values(?, ?, ?, ?, ?, ?, ?, ?, ?)")
		if err != nil {
			log.Println(err)
		}
		_, err = smt.Exec(html.EscapeString(company), html.EscapeString(email), html.EscapeString(material), html.EscapeString(process), html.EscapeString(samples), html.EscapeString(testfile), html.EscapeString(machine), html.EscapeString(requestedby), html.EscapeString(duedate))
		if err != nil {
			log.Println(err)
		}

	}
}

func delHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["ID"]
	db, err := sql.Open("mysql", DATABASE)
	if err != nil {
		log.Println(err)
	}
	defer db.Close()
	_, err = db.Query("delete from tests where id=?", html.EscapeString(id))
	if err != nil {
		log.Println(err)
	}
	io.WriteString(w, id+"deleted")
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/login", 301)
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
		value := map[string]string{
			"email": email,
			"level": "admin",
		}
		if encoded, err := cookieHandler.Encode("session", value); err == nil {
			cookie := &http.Cookie{
				Name:  "session",
				Value: encoded,
				Path:  "/",
			}
			http.SetCookie(w, cookie)
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
		smt, err := db.Prepare("insert into users(email, password) values(?, ?)")
		if err != nil {
			log.Println(err)
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Println(err)
		}
		_, err = smt.Exec(html.EscapeString(email), string(hashedPassword))
		if err != nil {
			log.Println(err)
		}
		http.Redirect(w, r, "/login", 302)

	}

}
func putHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	db, err := sql.Open("mysql", DATABASE)
	if err != nil {
		log.Println(err)
	}
	defer db.Close()
	switch r.Method {
	case "POST":

	case "GET":
		res := Tests{}
		err = db.QueryRow("select id, company, email, material, process, samples, testfile, samples , machine, requestedby, performedby, duedate, completion, status from tests where id=?", html.EscapeString(id)).Scan(&res.ID, &res.Company, &res.Email, &res.Material, &res.Process, &res.Samples, &res.TestFile, &res.SamplesRecieved, &res.Machine, &res.RequestedBy, &res.PerformedBy, &res.DueDate, &res.Completion, &res.Status)
		if err != nil {
			log.Println(err)
		}
		err = templates.ExecuteTemplate(w, "modify.html", &res)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}

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
	router.HandleFunc("/logut", logoutHandler)
	router.HandleFunc("/register", registerHandler)
	router.HandleFunc("/orders", ordersHandler)
	router.HandleFunc("/", rootHandler)
	err := http.ListenAndServe(PORT, router)
	if err != nil {
		log.Fatal(err)

	}
}
