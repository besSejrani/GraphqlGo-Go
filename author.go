package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/go-playground/validator.v9"

	"github.com/graphql-go/graphql"
	uuid "github.com/satori/go.uuid"
)

type Author struct {
	Id        string `json:"id,omitempty" validate:"omitempty,uuid"`
	FirstName string `json:"firstName,omitempty" validate:"required"`
	LastName  string `json:"lastName,omitempty" validate:"required"`
	UserName  string `json:"userName,omitempty" validate:"required"`
	Password  string `json:"password,omitempty" validate:"required,gte=4"`
}

var authorType *graphql.Object = graphql.NewObject(graphql.ObjectConfig{
	Name: "Author",
	Fields: graphql.Fields{
		"id": &graphql.Field{
			Type: graphql.String,
		},
		"firstName": &graphql.Field{
			Type: graphql.String,
		},
		"lastName": &graphql.Field{
			Type: graphql.String,
		},
		"userName": &graphql.Field{
			Type: graphql.String,
		},
		"password": &graphql.Field{
			Type: graphql.String,
		},
	},
})

var authorInputType *graphql.InputObject = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "AuthorInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": &graphql.InputObjectFieldConfig{
			Type: graphql.String,
		},
		"firstName": &graphql.InputObjectFieldConfig{
			Type: graphql.String,
		},
		"lastName": &graphql.InputObjectFieldConfig{
			Type: graphql.String,
		},
		"userName": &graphql.InputObjectFieldConfig{
			Type: graphql.String,
		},
		"password": &graphql.InputObjectFieldConfig{
			Type: graphql.String,
		},
	},
})

func RegisterEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "application/json")
	var author Author
	json.NewDecoder(r.Body).Decode(&author)

	validate := validator.New()
	err := validate.Struct(author)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(`{"message":"` + err.Error() + `"}`))
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(author.Password), 10)
	author.Password = string(hash)

	author.Id = uuid.Must(uuid.NewV4()).String()
	authors = append(authors, author)
	json.NewEncoder(w).Encode(authors)
}

func Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "application/json")
	var data Author
	json.NewDecoder(r.Body).Decode(&data)

	validate := validator.New()
	err := validate.StructExcept(data, "FirstName", "LastName")
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(`{"message":"` + err.Error() + `"}`))
		return
	}

	for _, author := range authors {
		if author.UserName == data.UserName {
			err := bcrypt.CompareHashAndPassword([]byte(author.Password), []byte(data.Password))
			if err != nil {
				w.WriteHeader(500)
				w.Write([]byte(`{"message":"invalid password" }`))
				return
			}
			claims := CustomJWTClaims{
				Id: author.Id,
				StandardClaims: jwt.StandardClaims{
					ExpiresAt: time.Now().Local().Add(time.Hour).Unix(),
					Issuer:    "bes",
				},
			}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := token.SignedString(JWT_SECRET)
			w.Write([]byte(`{"token":"` + tokenString + `"}`))
		}
	}
	json.NewEncoder(w).Encode(Author{})
}
