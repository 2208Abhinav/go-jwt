package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	jwt "github.com/dgrijalva/jwt-go"
	request "github.com/dgrijalva/jwt-go/request"
)

const (
	privKeyPath = "keys/app.rsa"
	pubKeyPath  = "keys/app.rsa.pub"
)

// verify key and sign key
var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

// User : credentials of an user.
type User struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

// Response struct used to jsonify the response body.
type Response struct {
	Text string `json:"text"`
}

// Token struct used to josnify jwt token for response.
type Token struct {
	TokenValue string `json:"token"`
}

// read the key files before starting http handlers
func init() {
	signKeyByte, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		log.Fatal("Error reading private key")
		return
	}
	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signKeyByte)
	if err != nil {
		log.Fatalf("[initKeys]: %s\n", err)
	}
	verifyKeyByte, err := ioutil.ReadFile(pubKeyPath)
	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyKeyByte)
	if err != nil {
		log.Fatal("Error reading private key")
		return
	}
}

func jsonResponse(response interface{}, w http.ResponseWriter) {
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

// reads the login credentials, checks them and creates JWT token
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	// decode into user struct
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Error in request body")
		return
	}
	// validate user credentials
	// this is just a mockup ;)
	if user.UserName != "abhinav" && user.Password != "pass" {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Wrong info")
		return
	}

	// create the signer for rsa 256
	signer := jwt.New(jwt.GetSigningMethod("RS256"))
	// create a map to store our claims
	claims := signer.Claims.(jwt.MapClaims)

	// set our claims
	claims["iss"] = "admin"
	claims["CustomUserInfo"] = struct {
		Name string
		Role string
	}{user.UserName, "Member"}

	// set the expire time
	claims["exp"] = time.Now().Add(time.Minute * 20).Unix()

	// Here we are sigining the token with our RSA private key so that
	// when we receive the token we can authenticate it with our RSA
	// public key.
	tokenString, err := signer.SignedString(signKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Sorry, error while Signing Token!")
		log.Printf("Token Signing error: %v\n", err)
		return
	}

	tokenResponse := Token{TokenValue: tokenString}
	jsonResponse(tokenResponse, w)
}

// Only accessible with a valid token
func authHandler(w http.ResponseWriter, r *http.Request) {
	// Validate the token
	// the header should have the token in the following schema.
	// Authorization: Bearer <token>
	token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor, keyLookupFunc)

	if err != nil {
		switch err.(type) {
		case *jwt.ValidationError: // something was wrong during the validation
			vErr := err.(*jwt.ValidationError)

			switch vErr.Errors {
			case jwt.ValidationErrorExpired:
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintln(w, "Token Expired, get a new one.")
				return

			default:
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintln(w, "Error while parsing token")
				log.Printf("Validation error: %+v\n", vErr.Errors)
				return
			}

		default: // something else went wrong
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Error while Parsing Token!")
			log.Printf("Token parse errors: %+v", err)
			return
		}
	}

	if token.Valid {
		response := Response{"Authorized to the system"}
		jsonResponse(response, w)
	} else {
		response := Response{"Invalid token"}
		jsonResponse(response, w)
	}
}

func keyLookupFunc(*jwt.Token) (interface{}, error) {
	// this is the public key to
	return verifyKey, nil
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/auth", authHandler).Methods("POST")

	server := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}
	log.Println("Listening...")
	server.ListenAndServe()
}
