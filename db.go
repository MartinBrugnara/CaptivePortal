package captive

import (
	"database/sql"
	"github.com/lib/pq"
	"log"
)

var (
	// String used to connect to postgresql
	ConnString string = "dbname=captive sslmode=disable encoding=utf-8"

	// singleton
	db *sql.DB
)

func InitDB() {
	var e error
	if db, e = sql.Connect("postgres", ConnString); e != nil {
		log.Fatal(fmt.Sprintf("[EE] DB connect %s: %s", ConnString, e.Error()))
	}
}
