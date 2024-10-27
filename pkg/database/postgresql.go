package database

import (
    "database/sql"
    "fmt"
    "log"
    "os"
    "strings"

    "github.com/joho/godotenv"
    _ "github.com/lib/pq" // Import the PostgreSQL driver
)

func Postgresql() *sql.DB {
    err := godotenv.Load()
    if err != nil {
        log.Fatal("cannot load .env file: ", err)
    }

    db, err := sql.Open("postgres", os.Getenv("postgresql"))
    if err != nil {
        panic(err.Error())
    }

    err = db.Ping()
    if err != nil {
        if strings.Contains(err.Error(), "password authentication failed") {
            log.Fatalf("Password authentication failed for user(invalid username or password).\nError: %s", err.Error())
        } else if strings.Contains(err.Error(), "period of time, or established connection failed because connected host has failed to respond.") {
            log.Fatalf("DNS lookup failed(Timeout). Check if the database server address is correct.\nError: %s", err.Error())
        } else if strings.Contains(err.Error(), "No connection could be made because the target machine actively refused it") {
            log.Fatalf("Connection refused: Check if the target machine is running and the port is correct. Ensure environment variables in the .env files are correctly set.\nError: %s", err.Error())
        } else {
            log.Fatalf("Error on connecting to database: %s\n", err.Error())
        }
    } else {
        fmt.Println("Connected to PostgreSQL")
    }

    return db
}
