package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
)

func Mariadb() *sql.DB {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("cannot load .env file: ", err)
	}

	db, err := sql.Open("mysql", os.Getenv("mariadb"))
	if err != nil {
		panic(err.Error())
	}
	fmt.Println("Connected mariadb")
	return db
}
