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

var templates = template.Must(template.ParseFiles("templates/index.html", "templates/orders.html", "templates/login.html", "templates/modify.html", "templates/register.html", "templates/new.html", "templates/customers.html"))
var cookieHandler = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32),
)

type Tests struct {
	ID              string `json:"id"`
	Company         string `json:"company"`
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
	db, err := sql.Open("mysql", DATABASE)
	if err != nil {
		log.Println(err)
	}
	defer db.Close()
	rows, err := db.Query("select id, company, material, process, samples, testfile, samples , machine, requestedby, performedby, duedate, completion, status from tests")
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
func customerHandler(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", 302)
	}
	vars := mux.Vars(r)
	id := vars["ID"]
	db, err := sql.Open("mysql", DATABASE)
	if err != nil {
		log.Println(err)
	}
	defer db.Close()
	rows, err := db.Query("select id, email, company, contactname, phone, address from users where id=?", html.EscapeString(id))
	if err != nil {
		log.Println(err)
	}
	b := Users{}
	for rows.Next() {
		rows.Scan(&b.ID, &b.Email, &b.Company, &b.ContactName, &b.Phone, &b.Address)
	}

	err = templates.ExecuteTemplate(w, "customer.html", &b)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func newHandler(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", 302)
	}
	switch r.Method {
	case "GET":
		err := templates.ExecuteTemplate(w, "new.html", "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case "POST":
		material := r.FormValue("material")
		process := r.FormValue("process")
		samples := r.FormValue("samples")
		testfile := r.FormValue("files")
		machine := r.FormValue("machine")
		duedate := r.FormValue("duedate")
		db, err := sql.Open("mysql", DATABASE)
		if err != nil {
			log.Println(err)
		}
		defer db.Close()
		smt, err := db.Prepare("insert into tests(company, material, process, samples, testfile, machine, requestedby, duedate) values(?, ?, ?, ?, ?, ?, ?, ?)")
		if err != nil {
			log.Println(err)
		}
		_, err = smt.Exec("dicks", html.EscapeString(material), html.EscapeString(process), html.EscapeString(samples), html.EscapeString(testfile), html.EscapeString(machine), "dicks", html.EscapeString(duedate))
		if err != nil {
			log.Println(err)
		}

	}
}

func doneHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["ID"]
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
		smt, err := db.Prepare("insert into users(email, company, contactname, phone, address) values(?, ?, ?, ?, ?)")
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
	_, err := r.Cookie("session")
	if err != nil {
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
		level := r.FormValue("level")
		db, err := sql.Open("mysql", DATABASE)
		if err != nil {
			log.Println(err)
		}
		defer db.Close()
		smt, err := db.Prepare("insert into users(email, password, level) values(?, ?, ?)")
		if err != nil {
			log.Println(err)
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Println(err)
		}
		_, err = smt.Exec(html.EscapeString(email), string(hashedPassword), html.EscapeString(level))
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
	_, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", 302)
	}
	http.Redirect(w, r, "/new", 302)

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
