package repositories

import (
	"auth-login/models"
	"database/sql"
	"fmt"
)

type IRepository interface {
	Login(req models.Login) (models.LoginResponse, error) 
}

type repository struct {
	db *sql.DB
}

func NewRepositorie(db *sql.DB) IRepository {
	return &repository{db: db}
}


func (r *repository) Login(req models.Login) (models.LoginResponse, error) {
	var (
		storedPassword string
		orgpplID      string
		response      models.LoginResponse
	)

	err := r.db.QueryRow(`
        SELECT 
            pplcr_password, orgppl_id 
        FROM 
            ppl_credential 
        JOIN 
            org_people ON pplcr_orgppl_id = orgppl_id 
        WHERE
            orgppl_email = $1`, req.OrgpplEmail).Scan(&storedPassword, &orgpplID)

	if err != nil {
		return models.LoginResponse{}, fmt.Errorf("user email not found: %w", err)
	}

	if req.PplcrPassword != storedPassword {
		return models.LoginResponse{}, fmt.Errorf("incorrect password")
	}

	response.OrgpplID = orgpplID

	return response, nil
}
