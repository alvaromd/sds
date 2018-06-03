package client

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

type User struct {
	Name      string `json:"name"`
	Password  string `json:"password"`
	Key       string `json:"key"`
	UserFiles Files  `json:"files"`
}

// Files struct array de ficheros
type Files struct {
	Files []File `json:"files"`
}

// File struct fichero
type File struct {
	ID   int       `json:"id"`
	Name string    `json:"file"`
	Size int64     `json:"size"`
	Time time.Time `json:"time"`
}

// Respuesta del servidor
type respToken struct {
	Ok    bool   `json:"ok"`
	Msg   string `json:"msg"`
	Token string `json:"token"`
}

// Chk function to check errors (saves lines of code)
func Chk(e error) {
	if e != nil {
		panic(e)
	}
}

/***
CLIENT
***/

func hashPass(password string) string {
	// Hasheamos la contraseña usando SHA512
	passwordHash := sha512.Sum512([]byte(password))
	slice := passwordHash[:]
	// Codificación base64
	pass := encode64(slice)

	return pass
}

func Client() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	var user User
	var regUser User
	var command string
	var checked bool
	var responseToken respToken
	var token string

	// Mientras no elija salir
	for command != "exit" {

		if command != "register" {
			if checked {
				fmt.Printf("Options: | list | upload | download | logout | exit |")
			} else {
				fmt.Printf("Options: | register | login | 2fauth | exit |")
			}
		}

		if command != "register" {
			fmt.Printf("\nCommand: ")
			fmt.Scanf("%s\n", &command)
		} else {
			command = "register"
		}

		switch command {
		// LOGIN USER with Jwt Token
		case "login":

			// Request user and password
			fmt.Printf("Username: ")
			fmt.Scanf("%s\n", &user.Name)

			fmt.Printf("Password: ")
			fmt.Scanf("%s\n", &user.Password)

			// Hashing password
			password := hashPass(user.Password)

			// Estructura con los valores a enviar en la peticion POST
			data := url.Values{}
			data.Set("username", user.Name)
			data.Set("password", password) // password (string) con hash y base64

			// Token auth
			r, err := client.PostForm("https://localhost:10443/login", data)
			Chk(err)

			message, _ := ioutil.ReadAll(r.Body)
			json.Unmarshal(message, &responseToken)

			// Convert JWT struct to string to pass through Query Param
			token = responseToken.Token

			// Check if login was successful
			if responseToken.Ok {
				checked = true
			} else {
				checked = false
			}

			fmt.Println(responseToken.Msg)

		// 2 factor authentication (optional login, not requested)
		case "2fauth":
			url := "https://localhost:10443/test"
			req, err := http.NewRequest("GET", url, nil)
			Chk(err)

			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := client.Do(req)
			Chk(err)

			content, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				log.Fatal(err)
			}

			fmt.Printf("%s", content)

		case "test":
			url := "https://localhost:10443/test"
			req, err := http.NewRequest("GET", url, nil)
			Chk(err)

			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := client.Do(req)
			Chk(err)

			content, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				log.Fatal(err)
			}

			fmt.Printf("%s", content)

		// REGISTER USER
		case "register":
			fmt.Printf("Username: ")
			fmt.Scanf("%s\n", &regUser.Name)

			fmt.Printf("Password: ")
			fmt.Scanf("%s\n", &regUser.Password)

			// Hasheamos contraseña con SHA512
			password := hashPass(regUser.Password)

			// Estructura con los valores a enviar en la peticion POST
			data := url.Values{}
			data.Set("username", regUser.Name)
			data.Set("password", password) // password (string) con hash y base64

			// POST request
			r, err := client.PostForm("https://localhost:10443/register", data)
			Chk(err)
			io.Copy(os.Stdout, r.Body)

			// Reset var
			command = ""
		// Shows files from user
		case "list":
			r, err := client.Get("https://localhost:10443/list?user=" + user.Name)
			Chk(err)

			bodyBytes, err := ioutil.ReadAll(r.Body)
			Chk(err)

			var ficheros Files

			erro := json.Unmarshal(bodyBytes, &ficheros)
			Chk(erro)

			fmt.Println("FILES")
			for _, f := range ficheros.Files {
				fmt.Print("Name: ")
				fmt.Println(f.Name)

				fmt.Print("  - Size: ")
				fmt.Println(f.Size)

				fmt.Print("  - Time: ")
				fmt.Println(f.Time)
			}

		case "upload":
			var filename string

			// Filename request
			fmt.Printf("Filename: ")
			fmt.Scanf("%s\n", &filename)

			data := url.Values{}
			data.Set("username", user.Name)
			data.Set("filename", filename) // password (string) with hash & base64

			// POST register
			r, err := client.PostForm("https://localhost:10443/upload", data)
			Chk(err)
			if err != nil {
				panic(err)
			}
			io.Copy(os.Stdout, r.Body)

		case "download":
			var filename string

			// Choose file to download
			fmt.Printf("Filename: ")
			fmt.Scanf("%s\n", &filename)

			data := url.Values{}
			data.Set("username", user.Name)
			data.Set("filename", filename) // password (string) with hash & base64

			// POST request
			r, err := client.PostForm("https://localhost:10443/download", data)
			Chk(err)
			if err == nil {
				checked = true
			}
			io.Copy(os.Stdout, r.Body)

		// Desconectar usuario
		case "logout":
			if checked {
				fmt.Printf("-- Logged out, login again --")
				fmt.Println()
				checked = false
				break
			}

		// Salir del programa
		case "exit":
			fmt.Println("Exiting...")
			break
		default:
			fmt.Println("Invalid command")
		}

		fmt.Println()
	}
}

// función para codificar de []bytes a string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// función para decodificar de string a []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	Chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

// Cifrar (con AES en este caso), adjunta el IV al principio
func encrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16)    // reservamos espacio para el IV al principio
	rand.Read(out[:16])                 // generamos el IV
	blk, err := aes.NewCipher(key)      // cifrador en bloque (AES), usa key
	Chk(err)                            // comprobamos el error
	ctr := cipher.NewCTR(blk, out[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out[16:], data)    // ciframos los datos
	return
}

// Descifrar (con AES en este caso)
func decrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)-16)     // la salida no va a tener el IV
	blk, err := aes.NewCipher(key)       // cifrador en bloque (AES), usa key
	Chk(err)                             // comprobamos el error
	ctr := cipher.NewCTR(blk, data[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out, data[16:])     // desciframos (doble cifrado) los datos
	return
}
