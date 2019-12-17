package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/dgrijalva/jwt-go"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/go-playground/validator.v9"

	"github.com/mitchellh/mapstructure"
	uuid "github.com/satori/go.uuid"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"

	"github.com/graphql-go/graphql"
)

type GraphQLPayload struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables"`
}

type CustomJWTClaims struct {
	Id string `json:"id"`
	jwt.StandardClaims
}

var authors []Author = []Author{
	Author{
		Id:        "1",
		FirstName: "Bes",
		LastName:  "Sejio",
		Password:  "123456789",
	},
	Author{
		Id:        "2",
		FirstName: "Besio",
		LastName:  "Sejion",
		Password:  "123456789",
	},
}

var articles []Article = []Article{
	Article{
		Id:      "1",
		Author:  "bes",
		Title:   "the road to ikigai",
		Content: "Confidence",
	},
}

var JWT_SECRET []byte = []byte("bes")

func ValidateJWT(t string) (interface{}, error) {
	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}
		return JWT_SECRET, nil
	})
	if err != nil {
		return nil, errors.New(`{"message":"` + err.Error() + `"}`)
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var tokenData CustomJWTClaims
		mapstructure.Decode(claims, &tokenData)
		return tokenData, nil
	} else {
		return nil, errors.New(`{"message":"invalid token" }`)
	}
}

var rootQuery *graphql.Object = graphql.NewObject(graphql.ObjectConfig{
	Name: "Query",
	Fields: graphql.Fields{

		"authors": &graphql.Field{

			Type: graphql.NewList(authorType),

			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				return authors, nil
			},
		},

		"author": &graphql.Field{
			Type: authorType,

			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{
					Type: graphql.NewNonNull(graphql.String),
				},
			},

			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				id := params.Args["id"].(string)
				for _, author := range authors {
					if author.Id == id {
						return author, nil
					}
				}
				return nil, nil
			},
		},

		"articles": &graphql.Field{
			Type: graphql.NewList(articleType),

			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				return articles, nil
			},
		},

		"article": &graphql.Field{
			Type: articleType,

			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{
					Type: graphql.NewNonNull(graphql.String),
				},
			},

			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				id := params.Args["id"].(string)
				for _, article := range articles {
					if article.Id == id {
						return article, nil
					}
				}
				return nil, nil
			},
		},
	},
})

var rootMutation *graphql.Object = graphql.NewObject(graphql.ObjectConfig{
	Name: "Mutation",
	Fields: graphql.Fields{
		"deleteAuthor": &graphql.Field{
			Type: graphql.NewList(authorType),
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{
					Type: graphql.NewNonNull(graphql.String),
				},
			},
			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				id := params.Args["id"].(string)

				for index, author := range authors {
					if author.Id == id {
						authors = append(authors[:index], authors[index+1:]...)
						return authors, nil
					}
				}
				return nil, nil
			},
		},

		"updateAuthor": &graphql.Field{
			Type: graphql.NewList(authorType),

			Args: graphql.FieldConfigArgument{
				"author": &graphql.ArgumentConfig{
					Type: authorInputType,
				},
			},

			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				var changes Author
				mapstructure.Decode(params.Args["author"], &changes)

				validate := validator.New()

				for index, author := range authors {
					if author.Id == changes.Id {
						if changes.FirstName != "" {
							author.FirstName = changes.FirstName
						}
						if changes.LastName != "" {
							author.LastName = changes.LastName
						}
						if changes.UserName != "" {
							author.UserName = changes.UserName
						}
						if changes.Password != "" {
							err := validate.Var(changes.Password, "gte=4")
							if err != nil {
								return nil, err
							}

							hash, _ := bcrypt.GenerateFromPassword([]byte(changes.Password), 10)
							author.Password = string(hash)
						}
						authors[index] = author
						return authors, nil
					}
				}
				return nil, nil
			},
		},

		"createArticle": &graphql.Field{
			Type: graphql.NewList(articleType),

			Args: graphql.FieldConfigArgument{
				"article": &graphql.ArgumentConfig{
					Type: articleInputType,
				},
			},

			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				var article Article
				mapstructure.Decode(params.Args["article"], &article)

				decoded, err := ValidateJWT(params.Context.Value("token").(string))
				if err != nil {
					return nil, err
				}

				validate := validator.New()
				err = validate.Struct(article)
				if err != nil {
					return nil, err
				}

				article.Id = uuid.Must(uuid.NewV4()).String()
				article.Author = decoded.(CustomJWTClaims).Id

				articles = append(articles, article)
				return articles, nil
			},
		},
	},
})

func home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "i'm home")
}

func main() {

	router := mux.NewRouter()
	schema, _ := graphql.NewSchema(graphql.SchemaConfig{
		Query:    rootQuery,
		Mutation: rootMutation,
	})

	router.HandleFunc("/", home)
	router.HandleFunc("/login", Login).Methods("POST")
	router.HandleFunc("/register", RegisterEndpoint).Methods("POST")

	router.HandleFunc("/graphql2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")

		var payload GraphQLPayload
		json.NewDecoder(r.Body).Decode(&payload)

		result := graphql.Do(graphql.Params{
			Schema:         schema,
			RequestString:  payload.Query,
			VariableValues: payload.Variables,
			Context:        context.WithValue(context.Background(), "token", r.URL.Query().Get("token")),
		})

		json.NewEncoder(w).Encode(result)
	})

	headers := handlers.AllowedHeaders(
		[]string{
			"Content-Type",
			"Authorization",
		},
	)

	methods := handlers.AllowedMethods(
		[]string{
			"GET",
			"POST",
			"DELETE",
			"PUT",
		},
	)

	origins := handlers.AllowedOrigins(
		[]string{
			"*",
		},
	)

	log.Fatal(http.ListenAndServe(
		":8800",
		handlers.CORS(headers, methods, origins)(router),
	))
}
