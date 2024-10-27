package repositories

import (
	"auth-login/models"
	"database/sql"
	"fmt"
)

type IRepository interface {
	Login(login models.Login) error
}

type repository struct {
	db *sql.DB
}

func NewRepositorie(db *sql.DB) IRepository {
	return &repository{db: db}
}

func (r *repository) Login(login models.Login ) error {
	var storedPassword string

	// ดึงรหัสผ่านที่เก็บไว้ในฐานข้อมูลโดยใช้อีเมล
	err := r.db.QueryRow(`
        SELECT 
            pplcr_password 
        FROM 
            ppl_credential 
        JOIN 
            org_people ON pplcr_orgppl_id = orgppl_id 
        WHERE
            orgppl_email = $1
    `, login.OrgpplEmail).Scan(&storedPassword)

	if err != nil {
		return fmt.Errorf("user email not found")
	}

	// ตรวจสอบรหัสผ่าน
	if login.PplcrPassword != storedPassword {
		return fmt.Errorf("incorrect password")
	}

	return nil
}
