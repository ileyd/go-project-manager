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

var templates = template.Must(template.ParseFiles("templates/index.html", "templates/orders.html", "templates/login.html", "templates/modify.html", "templates/register.html", "templates/new.html", "templates/customers.html", "templates/company.html"))
var cookieHandler = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32),
)

type Tests struct {
	ID           string `json:"id"`
	Customer     string `json:"customer"`
	DateReceived string `json:"datereceived"`
	SalesRep     string `json:"salesrep"`
	Samples      string `json:"samples"`
	Requirements string `json:"requirements"`
	DueDate      string `json:"duedate"`
	Dispatch     string `json:"dispatch"`
	Completion   string `json:"completion"`
	AppNumber    string `json:"appnumber"`
	Status       string `json:"status"`
	Comments     string `json:"comments"`
	Done         bool   `json:"done"`
}

type Page struct {
	Tests []Tests `json:"data"`
}

type New struct {
	Company []Company `json:"data"`
}

type Users struct {
	ID       string
	Email    string
	Password string
	Level    string
}
type Company struct {
	ID          string
	Email       string
	Company     string
	ContactName string
	Phone       string
	Address     string
}

func ordersHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", 302)
	}
	cookieValue := make(map[string]string)
	err = cookieHandler.Decode("session", cookie.Value, &cookieValue)
	if err != nil {
		log.Println(err)
	}
	level := cookieValue["level"]
	if level != "admin" {
		http.Redirect(w, r, "/login", 302)
	}

	db, err := sql.Open("mysql", DATABASE)
	if err != nil {
		log.Println(err)
	}
	defer db.Close()
	rows, err := db.Query("select id, customer, datereceived, salesrep, samples, requirements, duedate, dispatch, completion, appnumber, status, comments, done from tests")
	if err != nil {
		log.Println(err)
	}
	b := Page{Tests: []Tests{}}
	for rows.Next() {
		res := Tests{}
		rows.Scan(&res.ID, &res.Customer, &res.DateReceived, &res.SalesRep, &res.Samples, &res.Requirements, &res.DueDate, &res.Dispatch, &res.Completion, &res.AppNumber, &res.Status, &res.Comments, &res.Done)
		b.Tests = append(b.Tests, res)
	}

	err = templates.ExecuteTemplate(w, "orders.html", &b)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
func customerHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", 302)
	}
	cookieValue := make(map[string]string)
	err = cookieHandler.Decode("session", cookie.Value, &cookieValue)
	if err != nil {
		log.Println(err)
	}
	level := cookieValue["level"]
	if level != "admin" {
		http.Redirect(w, r, "/login", 302)
	}

	vars := mux.Vars(r)
	id := vars["id"]
	db, err := sql.Open("mysql", DATABASE)
	if err != nil {
		log.Println(err)
	}
	defer db.Close()
	b := Company{}
	err = db.QueryRow("select * from companies where id=?", html.EscapeString(id)).Scan(&b.ID, &b.Email, &b.Company, &b.ContactName, &b.Phone, &b.Address)
	if err != nil {
		log.Println(err)
	}

	err = templates.ExecuteTemplate(w, "customers.html", &b)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func newHandler(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", 302)
	}
	db, err := sql.Open("mysql", DATABASE)
	if err != nil {
		log.Println(err)
	}
	defer db.Close()

	switch r.Method {
	case "GET":
		rows, err := db.Query("select company from companies")
		if err != nil {
			log.Println(err)
		}

		b := New{Company: []Company{}}
		for rows.Next() {
			res := Company{}
			rows.Scan(&res.Company)
			b.Company = append(b.Company, res)
		}

		err = templates.ExecuteTemplate(w, "new.html", &b)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case "POST":
		company := r.FormValue("company")
		datereceived := r.FormValue("datereceived")
		salesrep := r.FormValue("salesrep")
		samples := r.FormValue("samples")
		requirements := r.FormValue("requirements")
		duedate := r.FormValue("duedate")
		dispatch := r.FormValue("dispatch")
		completion := r.FormValue("completion")
		appnumber := r.FormValue("appnumber")
		status := r.FormValue("status")
		comments := r.FormValue("comments")

		smt, err := db.Prepare("insert into tests(customer, datereceived, salesrep, samples, requirements, duedate, dispatch, completion, appnumber, status, comments, done) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
		if err != nil {
			log.Println(err)
		}
		_, err = smt.Exec(html.EscapeString(company), html.EscapeString(datereceived), html.EscapeString(salesrep), html.EscapeString(samples), html.EscapeString(requirements), html.EscapeString(duedate), html.EscapeString(dispatch), html.EscapeString(completion), html.EscapeString(appnumber), html.EscapeString(status), html.EscapeString(comments), false)
		if err != nil {
			log.Println(err.Error())
		}

	}
}

func doneHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", 302)
	}
	cookieValue := make(map[string]string)
	err = cookieHandler.Decode("session", cookie.Value, &cookieValue)
	if err != nil {
		log.Println(err)
	}
	level := cookieValue["level"]
	if level != "admin" {
		http.Redirect(w, r, "/login", 302)
	}
	vars := mux.Vars(r)
	id := vars["id"]
	db, err := sql.Open("mysql", DATABASE)
	if err != nil {
		log.Println(err)
	}
	defer db.Close()
	_, err = db.Query("update tests set done=true where id=?", html.EscapeString(id))
	if err != nil {
		log.Println(err)
	}
	io.WriteString(w, id+" completed")
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
		var hashedPassword, level string
		err = db.QueryRow("select password, level from users where email=?", html.EscapeString(email)).Scan(&hashedPassword, &level)
		if err == sql.ErrNoRows {
			http.Redirect(w, r, "/login", 303)
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
			"level": level,
		}
		if encoded, err := cookieHandler.Encode("session", value); err == nil {
			cookie := &http.Cookie{
				Name:  "session",
				Value: encoded,
				Path:  "/",
			}
			http.SetCookie(w, cookie)
		}
		http.Redirect(w, r, "/", 302)

	}

}
func newcompanyHandler(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", 302)
	}
	switch r.Method {
	case "GET":
		err := templates.ExecuteTemplate(w, "company.html", "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case "POST":
		email := r.FormValue("email")
		name := r.FormValue("name")
		company := r.FormValue("company")
		phone := r.FormValue("phone")
		address := r.FormValue("address")
		db, err := sql.Open("mysql", DATABASE)
		if err != nil {
			log.Println(err)
		}
		defer db.Close()
		smt, err := db.Prepare("insert into companies(email, company, contactname, phone, address) values(?, ?, ?, ?, ?)")
		if err != nil {
			log.Println(err)
		}
		if err != nil {
			log.Println(err)
		}
		_, err = smt.Exec(html.EscapeString(email), html.EscapeString(company), html.EscapeString(name), html.EscapeString(phone), html.EscapeString(address))
		if err != nil {
			log.Println(err)
		}

	}

}
func registerHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", 302)
	}
	cookieValue := make(map[string]string)
	err = cookieHandler.Decode("session", cookie.Value, &cookieValue)
	if err != nil {
		log.Println(err)
	}
	level := cookieValue["level"]
	if level != "admin" {
		http.Redirect(w, r, "/login", 302)
	}

	switch r.Method {
	case "GET":
		err := templates.ExecuteTemplate(w, "register.html", "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case "POST":
		email := r.FormValue("email")
		password := r.FormValue("password")
		name := r.FormValue("name")
		level := r.FormValue("level")
		db, err := sql.Open("mysql", DATABASE)
		if err != nil {
			log.Println(err)
		}
		defer db.Close()
		smt, err := db.Prepare("insert into users(email, password, name, level) values(?, ?, ?, ?)")
		if err != nil {
			log.Println(err)
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Println(err)
		}
		_, err = smt.Exec(html.EscapeString(email), string(hashedPassword), html.EscapeString(name), html.EscapeString(level))
		if err != nil {
			log.Println(err)
		}
		http.Redirect(w, r, "/login", 302)

	}

}
func putHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", 302)
	}
	cookieValue := make(map[string]string)
	err = cookieHandler.Decode("session", cookie.Value, &cookieValue)
	if err != nil {
		log.Println(err)
	}
	level := cookieValue["level"]
	if level != "admin" {
		http.Redirect(w, r, "/login", 302)
	}

	vars := mux.Vars(r)
	id := vars["id"]
	db, err := sql.Open("mysql", DATABASE)
	if err != nil {
		log.Println(err)
	}
	defer db.Close()
	switch r.Method {
	case "POST":
		company := r.FormValue("company")
		datereceived := r.FormValue("datereceived")
		salesrep := r.FormValue("salesrep")
		samples := r.FormValue("samples")
		requirements := r.FormValue("requirements")
		duedate := r.FormValue("duedate")
		dispatch := r.FormValue("dispatch")
		completion := r.FormValue("completion")
		appnumber := r.FormValue("appnumber")
		status := r.FormValue("status")
		comments := r.FormValue("comments")

		smt, err := db.Prepare("Update tests set customer=?, datereceived=?, salesrep=?, samples=?, requirements=?, duedate=?, dispatch=?, completion=?, appnumber=?, status=?, comments=? where id=?")
		if err != nil {
			log.Println(err)
		}
		err = smt.Exec(html.EscapeString(company), html.EscapeString(datereceived), html.EscapeString(salesrep), html.EscapeString(samples), html.EscapeString(requirements), html.EscapeString(duedate), html.EscapeString(dispatch), html.EscapeString(completion), html.EscapeString(appnumber), html.EscapeString(status), html.EscapeString(comments))
		if err != nil {
			log.Println(err)
		}

	case "GET":
		res := Tests{}
		rows, err := db.Query("select id, customer, datereceived, salesrep, samples, requirements, duedate, dispatch, completion, appnumber, status, comments, done from tests where id=?", html.EscapeString(id))
		if err != nil {
			log.Println(err)
		}
		for rows.Next() {
			rows.Scan(&res.ID, &res.Customer, &res.DateReceived, &res.SalesRep, &res.Samples, &res.Requirements, &res.DueDate, &res.Dispatch, &res.Completion, &res.AppNumber, &res.Status, &res.Comments, &res.Done)
		}
		err = templates.ExecuteTemplate(w, "modify.html", &res)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}

}
func rootHandler(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", 302)
	}
	err = templates.ExecuteTemplate(w, "index.html", "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

}

func main() {

	router := mux.NewRouter()
	router.HandleFunc("/new", newHandler)
	router.HandleFunc("/newcompany", newcompanyHandler)
	router.HandleFunc("/done/{id}", doneHandler)
	router.HandleFunc("/put/{id}", putHandler)
	router.HandleFunc("/customer/{id}", customerHandler)
	router.HandleFunc("/login", loginHandler)
	router.HandleFunc("/logout", logoutHandler)
	router.HandleFunc("/register", registerHandler)
	router.HandleFunc("/orders", ordersHandler)
	router.HandleFunc("/", rootHandler)
	err := http.ListenAndServe(PORT, router)
	if err != nil {
		log.Fatal(err)

	}
}
