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
	Name         string `json:"name"`
	Password     string `json:"password"`
	Key          string `json:"key"`
	FAuth        string `json:"fauth"`
	FAuthEnabled bool   `json:"fauthenabled"`
	UserFiles    Files  `json:"files"`
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
type resp struct {
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
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
	var token string

	fmt.Println("\n###### REMOTE BACKUP PROJECT ######")
	fmt.Println("> SDS 2018 | UA")
	fmt.Println("> Created by: Alvaro Muñoz Delgado\n")

	for command != "exit" {
		if command != "register" {
			if checked {
				fmt.Println("> Select an option, " + user.Name)
				fmt.Printf("list | upload | download | delete | logout | exit")
			} else {
				fmt.Println("> Select an option")
				fmt.Printf("login | register | exit")
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
			var twofact string
			var responseToken respToken
			var newToken respToken

			token = ""

			fmt.Println("\n> Login")

			// Request user and password
			fmt.Printf("Username: ")
			fmt.Scanf("%s\n", &user.Name)

			fmt.Printf("Password: ")
			fmt.Scanf("%s\n", &user.Password)

			// Hashing password
			password := hashPass(user.Password)

			data := url.Values{}
			data.Set("username", user.Name)
			data.Set("password", password) // password (string) with hash & base64

			fmt.Printf("Would you like to use Two-factor authentication? (Y) (N): ")
			fmt.Scanf("%s\n", &twofact)

			if twofact == "Y" {
				var respFA resp
				// Double auth factor enabled
				disableFA, err := client.PostForm("https://localhost:10443/disableTwoFA", data)
				Chk(err)

				respDisableFA, _ := ioutil.ReadAll(disableFA.Body)
				json.Unmarshal(respDisableFA, &respFA)
			}

			// Token auth
			r, err := client.PostForm("https://localhost:10443/login", data)
			Chk(err)

			message, _ := ioutil.ReadAll(r.Body)
			json.Unmarshal(message, &responseToken)

			// Convert JWT struct to string to pass through Query Param
			token = responseToken.Token

			if twofact == "Y" {
				// Get fauth from user
				var fauth resp

				dataSecret := url.Values{}
				dataSecret.Set("username", user.Name)

				// Obtain secret key for this user
				reqFauth, err := client.PostForm("https://localhost:10443/getFauth", dataSecret)
				Chk(err)

				contentFauth, _ := ioutil.ReadAll(reqFauth.Body)
				json.Unmarshal(contentFauth, &fauth)

				// Token from mobile
				var otpToken string
				fmt.Printf("Write the numbers that appears on your mobile screen: ")
				fmt.Scanf("%s\n", &otpToken)

				// Verify OTP Token
				req, err := http.NewRequest("POST", "https://localhost:10443/2fauth", nil)
				Chk(err)

				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("otpToken", otpToken)
				req.Header.Set("secret", fauth.Msg)

				response, err := client.Do(req)
				Chk(err)

				tokenOTP, _ := ioutil.ReadAll(response.Body)
				json.Unmarshal(tokenOTP, &newToken)

				response.Body.Close()
				if err != nil {
					log.Fatal(err)
				}

				// Saving authorized 2FA token
				token = newToken.Token

				var respFA resp
				// Double auth factor enabled
				enableFA, err := client.PostForm("https://localhost:10443/enableTwoFA", dataSecret)
				Chk(err)

				respEnableFA, _ := ioutil.ReadAll(enableFA.Body)
				json.Unmarshal(respEnableFA, &respFA)

			}

			// Check if login was successful
			if newToken.Ok || responseToken.Ok {
				checked = true
			} else {
				checked = false
			}

			fmt.Printf("> ")
			fmt.Println(responseToken.Msg)
			fmt.Println(newToken.Msg)

		// REGISTER USER
		case "register":
			fmt.Println("\n> Register new user")

			var userKey string

			fmt.Printf("Username: ")
			fmt.Scanf("%s\n", &regUser.Name)

			fmt.Printf("Password: ")
			fmt.Scanf("%s\n", &regUser.Password)

			// Hasheamos contraseña con SHA512
			password := hashPass(regUser.Password)

			// Generate secret key
			req, err := http.NewRequest("GET", "https://localhost:10443/gen-secret", nil)
			Chk(err)
			resp, err := client.Do(req)
			Chk(err)

			content, err := ioutil.ReadAll(resp.Body)

			resp.Body.Close()
			if err != nil {
				log.Fatal(err)
			}

			// Save secret key
			json.Unmarshal(content, &userKey)

			fmt.Println("This is your code for double factor auth, write it down: " + userKey)

			// Estructura con los valores a enviar en la peticion POST
			data := url.Values{}
			data.Set("username", regUser.Name)
			data.Set("password", password) // password (string) con hash y base64
			data.Set("fauth", userKey)

			// POST request
			r, err := client.PostForm("https://localhost:10443/register", data)
			Chk(err)
			io.Copy(os.Stdout, r.Body)

			// Reset var
			command = ""
		// Shows files from user
		case "list":
			fmt.Println("\n> List user files")

			r, err := http.NewRequest("GET", "https://localhost:10443/list?user="+user.Name, nil)
			Chk(err)

			r.Header.Set("Authorization", "Bearer "+token)

			response, err := client.Do(r)
			Chk(err)

			if err != nil {
				log.Fatal(err)
			}

			content, err := ioutil.ReadAll(response.Body)
			Chk(err)

			response.Body.Close()

			var ficheros Files

			json.Unmarshal(content, &ficheros)

			if ficheros.Files != nil {
				fmt.Println("\n-- FILES --")
				for _, f := range ficheros.Files {
					fmt.Print("Name: ")
					fmt.Println(f.Name)

					fmt.Print("  - Size: ")
					fmt.Println(f.Size)

					fmt.Print("  - Time: ")
					fmt.Println(f.Time)
				}
			} else {
				fmt.Print("You have no files\n")
			}

		case "upload":
			fmt.Println("\n> Upload file")

			var filename string
			var response resp

			// Filename request
			fmt.Printf("Filename: ")
			fmt.Scanf("%s\n", &filename)

			r, err := http.NewRequest("POST", "https://localhost:10443/upload", nil)
			Chk(err)

			r.Header.Set("Authorization", "Bearer "+token)
			r.Header.Set("username", user.Name)
			r.Header.Set("filename", filename)

			resp, _ := client.Do(r)
			Chk(err)

			if err != nil {
				log.Fatal(err)
			}

			content, err := ioutil.ReadAll(resp.Body)

			resp.Body.Close()
			if err != nil {
				log.Fatal(err)
			}

			// Save secret key
			json.Unmarshal(content, &response)

			resp.Body.Close()

			fmt.Printf("> ")
			fmt.Println(response.Msg)

		case "download":
			fmt.Println("\n> Download file")

			var filename string
			var response resp

			// Choose file to download
			fmt.Printf("Filename: ")
			fmt.Scanf("%s\n", &filename)

			r, err := http.NewRequest("POST", "https://localhost:10443/download", nil)
			Chk(err)
			r.Header.Set("Authorization", "Bearer "+token)
			r.Header.Set("username", user.Name)
			r.Header.Set("filename", filename)

			resp, _ := client.Do(r)
			Chk(err)

			if err != nil {
				log.Fatal(err)
			}

			content, err := ioutil.ReadAll(resp.Body)

			resp.Body.Close()
			if err != nil {
				log.Fatal(err)
			}

			// Save secret key
			json.Unmarshal(content, &response)

			resp.Body.Close()

			fmt.Println(response.Msg)

		case "delete":
			fmt.Println("\n> Delete user file")

			var filename string
			var response resp

			// Choose file to download
			fmt.Printf("Filename: ")
			fmt.Scanf("%s\n", &filename)

			r, err := http.NewRequest("POST", "https://localhost:10443/delete", nil)
			Chk(err)
			r.Header.Set("Authorization", "Bearer "+token)
			r.Header.Set("username", user.Name)
			r.Header.Set("filename", filename)

			resp, _ := client.Do(r)
			Chk(err)

			if err != nil {
				log.Fatal(err)
			}

			content, err := ioutil.ReadAll(resp.Body)

			resp.Body.Close()
			if err != nil {
				log.Fatal(err)
			}

			// Save secret key
			json.Unmarshal(content, &response)

			resp.Body.Close()

			fmt.Println(response.Msg)

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

		/*
			case "2fauth":
				fmt.Println("\n> Two-factor authentication")

				var enable string
				var disable string

				// Get fauth from user
				var fauth resp

				dataSecret := url.Values{}
				dataSecret.Set("username", user.Name)

				reqFauth, err := client.PostForm("https://localhost:10443/getFauth", dataSecret)
				Chk(err)

				contentFauth, _ := ioutil.ReadAll(reqFauth.Body)
				json.Unmarshal(contentFauth, &fauth)

				var enabled resp

				// Token auth
				checkFA, err := client.PostForm("https://localhost:10443/checkUserFA", dataSecret)
				Chk(err)

				fa, _ := ioutil.ReadAll(checkFA.Body)
				json.Unmarshal(fa, &enabled)

				doubleFA = enabled.Ok

				if !doubleFA {
					fmt.Print("Two factor authentication is not enabled. Enable it? (Y) (N):  ")
					fmt.Scanf("%s\n", &enable)

					if enable == "Y" {
						// Token from mobile
						var otpToken string
						fmt.Printf("Write the numbers that appears on your mobile screen: ")
						fmt.Scanf("%s\n", &otpToken)

						req, err := http.NewRequest("POST", "https://localhost:10443/2fauth", nil)
						Chk(err)

						req.Header.Set("Authorization", "Bearer "+token)
						req.Header.Set("otpToken", otpToken)
						req.Header.Set("secret", fauth.Msg)

						response, err := client.Do(req)
						Chk(err)

						response.Body.Close()
						if err != nil {
							log.Fatal(err)
						}

						var respFA resp
						// Double auth factor enabled
						enableFA, err := client.PostForm("https://localhost:10443/enableTwoFA", dataSecret)
						Chk(err)

						respEnableFA, _ := ioutil.ReadAll(enableFA.Body)
						json.Unmarshal(respEnableFA, &respFA)

						fmt.Println(respFA.Msg)
					}
				} else {
					fmt.Print("Two factor authentication is enabled. Disable it? (Y) (N):  ")
					fmt.Scanf("%s\n", &disable)

					if disable == "Y" {
						var respFA resp
						// Double auth factor enabled
						disableFA, err := client.PostForm("https://localhost:10443/disableTwoFA", dataSecret)
						Chk(err)

						respDisableFA, _ := ioutil.ReadAll(disableFA.Body)
						json.Unmarshal(respDisableFA, &respFA)

						fmt.Println(respFA.Msg)
					}
				}
		*/
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
