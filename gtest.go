package main

import (
	"database/sql"
	"html"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	// mysql driver
	_ "github.com/go-sql-driver/mysql"
)

const (
	// ADDRESS that tracker will return links for
	ADDRESS     = "http://localhost:9900"
	UPDIRECTORY = "/tmp/"
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

var templates = template.Must(template.ParseFiles("templates/index.html", "templates/login.html", "templates/modify.html", "templates/register.html", "templates/new.html", "templates/customers.html", "templates/company.html", "templates/files.html"))
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

type Files struct {
	ID        string
	Name      string
	AppNumber string
}

type FilesPage struct {
	Files     []Files
	AppNumber string
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

func checkErr(err error) {
	if err != nil {
		log.Println(err.Error())
	}
}

func getCookieVars(r *http.Request) (string, string, error) {
	cookie, err := r.Cookie("session")
	cookieValue := make(map[string]string)
	if err != nil {
		return "", "", err
	}
	err = cookieHandler.Decode("session", cookie.Value, &cookieValue)
	if err != nil {
		return "", "", err
	}
	level := cookieValue["level"]
	name := cookieValue["name"]
	return name, level, nil

}

func ordersHandler(w http.ResponseWriter, r *http.Request) {

	name, level, err := getCookieVars(r)
	if err != nil {
		http.Redirect(w, r, "/login", 302)
		return
	}

	db, err := sql.Open("mysql", DATABASE)
	checkErr(err)
	defer db.Close()
	var rows *sql.Rows
	if level == "admin" {
		rows, err = db.Query("select id, customer, salesrep, samples, requirements, done, datereceived, duedate, dispatch, appnumber, status, comments from tests")
	} else {
		rows, err = db.Query("select id, customer, salesrep, samples, requirements, done, datereceived, duedate, dispatch, appnumber, status, comments from tests where salesrep=?", html.EscapeString(name))
	}
	checkErr(err)

	b := Page{Tests: []Tests{}}
	for rows.Next() {
		res := Tests{}
		rows.Scan(&res.ID, &res.Customer, &res.SalesRep, &res.Samples, &res.Requirements, &res.Done, &res.DateReceived, &res.DueDate, &res.Dispatch, &res.AppNumber, &res.Status, &res.Comments)
		b.Tests = append(b.Tests, res)
	}

	err = templates.ExecuteTemplate(w, "index.html", &b)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
func customerHandler(w http.ResponseWriter, r *http.Request) {
	_, _, err := getCookieVars(r)
	if err != nil {
		http.Redirect(w, r, "/login", 302)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]
	db, err := sql.Open("mysql", DATABASE)
	checkErr(err)

	defer db.Close()
	b := Company{}
	err = db.QueryRow("select * from companies where company=?", html.EscapeString(id)).Scan(&b.ID, &b.Email, &b.Company, &b.ContactName, &b.Phone, &b.Address)
	checkErr(err)

	err = templates.ExecuteTemplate(w, "customers.html", &b)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func newHandler(w http.ResponseWriter, r *http.Request) {
	name, _, err := getCookieVars(r)
	if err != nil {
		http.Redirect(w, r, "/login", 302)
		return
	}

	db, err := sql.Open("mysql", DATABASE)
	checkErr(err)

	defer db.Close()

	switch r.Method {
	case "GET":
		rows, err := db.Query("select company from companies")
		checkErr(err)

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
		samples := r.FormValue("samples")
		requirements := r.FormValue("requirements")
		comments := r.FormValue("comments")

		smt, err := db.Prepare("insert into tests(customer, datereceived, salesrep, samples, requirements, duedate, dispatch, completion, appnumber, status, comments, done) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
		checkErr(err)

		_, err = smt.Exec(html.EscapeString(company), "", name, html.EscapeString(samples), html.EscapeString(requirements), "", "", "", "", "", html.EscapeString(comments), false)
		checkErr(err)

		http.Redirect(w, r, "/new", 302)

	}
}

func delHandler(w http.ResponseWriter, r *http.Request) {
	_, level, err := getCookieVars(r)
	if err != nil {
		http.Redirect(w, r, "/login", 302)
		return
	}

	if level != "admin" {
		http.Redirect(w, r, "/login", 302)
		return
	}

	if level == "admin" {
		vars := mux.Vars(r)
		id := vars["id"]
		db, err := sql.Open("mysql", DATABASE)
		checkErr(err)

		defer db.Close()
		_, err = db.Query("delete from tests where id=?", html.EscapeString(id))
		checkErr(err)

		http.Redirect(w, r, "/", 302)
	}
}
func doneHandler(w http.ResponseWriter, r *http.Request) {
	_, level, err := getCookieVars(r)
	if err != nil {
		http.Redirect(w, r, "/login", 302)
		return
	}

	if level != "admin" {
		http.Redirect(w, r, "/login", 302)
		return
	}

	if level == "admin" {
		vars := mux.Vars(r)
		id := vars["id"]
		db, err := sql.Open("mysql", DATABASE)
		if err != nil {
			log.Println(err)
		}
		defer db.Close()
		var status bool
		err = db.QueryRow("select done from tests where id=?", html.EscapeString(id)).Scan(&status)

		checkErr(err)

		if status == true {
			_, err = db.Query("update tests set done=false where id=?", html.EscapeString(id))
			checkErr(err)
		}
		if status == false {
			_, err = db.Query("update tests set done=true where id=?", html.EscapeString(id))
			checkErr(err)
		}

		http.Redirect(w, r, "/", 302)

	}
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
		checkErr(err)

		defer db.Close()
		var hashedPassword []byte
		var level, name string
		err = db.QueryRow("select password, name, level from users where email=?", html.EscapeString(email)).Scan(&hashedPassword, &name, &level)
		if err == sql.ErrNoRows {
			http.Redirect(w, r, "/login", 303)
			return
		}
		checkErr(err)

		err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
		if err == nil {
			value := map[string]string{
				"email": email,
				"name":  name,
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
		http.Redirect(w, r, "/login", 302)

	}

}
func newcompanyHandler(w http.ResponseWriter, r *http.Request) {
	_, _, err := getCookieVars(r)
	if err != nil {
		http.Redirect(w, r, "/login", 302)
		return
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
		checkErr(err)

		defer db.Close()
		smt, err := db.Prepare("insert into companies(email, company, contactname, phone, address) values(?, ?, ?, ?, ?)")
		checkErr(err)

		_, err = smt.Exec(html.EscapeString(email), html.EscapeString(company), html.EscapeString(name), html.EscapeString(phone), html.EscapeString(address))
		checkErr(err)

		http.Redirect(w, r, "/", 302)

	}

}
func registerHandler(w http.ResponseWriter, r *http.Request) {
	_, level, err := getCookieVars(r)
	if err != nil {
		http.Redirect(w, r, "/login", 302)
		return
	}

	if level != "admin" {
		http.Redirect(w, r, "/login", 302)
		return
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
		checkErr(err)

		defer db.Close()
		smt, err := db.Prepare("insert into users(email, password, name, level) values(?, ?, ?, ?)")
		checkErr(err)

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		checkErr(err)

		_, err = smt.Exec(html.EscapeString(email), hashedPassword, html.EscapeString(name), html.EscapeString(level))
		checkErr(err)

		http.Redirect(w, r, "/login", 302)

	}

}
func filesHandler(w http.ResponseWriter, r *http.Request) {
	_, _, err := getCookieVars(r)
	if err != nil {
		http.Redirect(w, r, "/login", 302)
		return
	}

	vars := mux.Vars(r)
	appnumber := vars["appnumber"]
	db, err := sql.Open("mysql", DATABASE)
	checkErr(err)

	defer db.Close()
	switch r.Method {
	case "POST":
		reader, err := r.MultipartReader()
		checkErr(err)

		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}

			if part.FileName() == "" {
				continue
			}

			file := part.FileName()
			dst, err := os.Create(UPDIRECTORY + file)
			checkErr(err)

			defer dst.Close()
			// save uploaded data to created file
			_, err = io.Copy(dst, part)
			checkErr(err)

			smt, err := db.Prepare("insert into files(file, appnumber) values(?, ?)")
			checkErr(err)

			_, err = smt.Exec(file, html.EscapeString(appnumber))
			checkErr(err)
		}

		http.Redirect(w, r, "/files/"+appnumber, 302)

	case "GET":
		b := FilesPage{Files: []Files{}}
		b.AppNumber = appnumber
		rows, err := db.Query("select id, file, appnumber from files where appnumber=?", html.EscapeString(appnumber))
		checkErr(err)

		for rows.Next() {
			res := Files{}
			rows.Scan(&res.ID, &res.Name, &res.AppNumber)
			b.Files = append(b.Files, res)

		}
		err = templates.ExecuteTemplate(w, "files.html", &b)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}

}
func putHandler(w http.ResponseWriter, r *http.Request) {
	_, level, err := getCookieVars(r)
	if err != nil {
		http.Redirect(w, r, "/login", 302)
		return
	}

	if level != "admin" {
		http.Redirect(w, r, "/login", 302)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]
	db, err := sql.Open("mysql", DATABASE)
	checkErr(err)

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
		appnumber := r.FormValue("appnumber")
		status := r.FormValue("status")
		comments := r.FormValue("comments")

		smt, err := db.Prepare("Update tests set customer=?, datereceived=?, salesrep=?, samples=?, requirements=?, duedate=?, dispatch=?, appnumber=?, status=?, comments=? where id=?")
		checkErr(err)

		_, err = smt.Exec(html.EscapeString(company), html.EscapeString(datereceived), html.EscapeString(salesrep), html.EscapeString(samples), html.EscapeString(requirements), html.EscapeString(duedate), html.EscapeString(dispatch), html.EscapeString(appnumber), html.EscapeString(status), html.EscapeString(comments), html.EscapeString(id))
		checkErr(err)

		http.Redirect(w, r, "/", 302)

	case "GET":
		res := Tests{}
		rows, err := db.Query("select id, customer, datereceived, salesrep, samples, requirements, duedate, dispatch, appnumber, status, comments, done from tests where id=?", html.EscapeString(id))
		checkErr(err)

		for rows.Next() {
			rows.Scan(&res.ID, &res.Customer, &res.DateReceived, &res.SalesRep, &res.Samples, &res.Requirements, &res.DueDate, &res.Dispatch, &res.AppNumber, &res.Status, &res.Comments, &res.Done)
		}
		err = templates.ExecuteTemplate(w, "modify.html", &res)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}

}

func main() {

	router := mux.NewRouter()
	router.HandleFunc("/new", newHandler)
	router.HandleFunc("/newcompany", newcompanyHandler)
	router.HandleFunc("/done/{id}", doneHandler)
	router.HandleFunc("/put/{id}", putHandler)
	router.HandleFunc("/del/{id}", delHandler)
	router.HandleFunc("/files/{appnumber}", filesHandler)
	router.HandleFunc("/customer/{id}", customerHandler)
	router.HandleFunc("/login", loginHandler)
	router.HandleFunc("/logout", logoutHandler)
	router.HandleFunc("/register", registerHandler)
	router.HandleFunc("/", ordersHandler)
	router.Handle("/static/{rest}", http.StripPrefix("/static/", http.FileServer(http.Dir(UPDIRECTORY))))
	err := http.ListenAndServe(PORT, router)
	if err != nil {
		log.Fatal(err)

	}
}
