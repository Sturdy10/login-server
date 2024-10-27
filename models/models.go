package models

type Login struct {
	OrgpplEmail   string `json:"email" binding:"required"` 
	PplcrPassword string `json:"password"`
}



type LoginResponse struct {
	OrgpplID string `json:"uid"`
}
