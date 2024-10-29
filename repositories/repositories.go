package repositories

import (
	"auth-login/models"
	"database/sql"
	"fmt"
)

type IRepository interface {
	Login(login models.Login) (models.LoginResponse, error) 
}

type repository struct {
	db *sql.DB
}

func NewRepositorie(db *sql.DB) IRepository {
	return &repository{db: db}
}


func (r *repository) Login(login models.Login) (models.LoginResponse, error) {
	var storedPassword string
	var orgpplID string 

	err := r.db.QueryRow(`
        SELECT 
            pplcr_password, orgppl_id 
        FROM 
            ppl_credential 
        JOIN 
            org_people ON pplcr_orgppl_id = orgppl_id 
        WHERE
            orgppl_email = $1
    `, login.OrgpplEmail).Scan(&storedPassword, &orgpplID)

	if err != nil {
		return models.LoginResponse{}, fmt.Errorf("user email not found")
	}

	// ตรวจสอบรหัสผ่าน
	if login.PplcrPassword != storedPassword {
		return models.LoginResponse{}, fmt.Errorf("incorrect password")
	}

	response := models.LoginResponse{
		OrgpplID: orgpplID, 
	}

	
	return response, nil
}

