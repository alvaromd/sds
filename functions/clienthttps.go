package functions

import (
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
)

/***
CLIENTE
***/

func hashPass(password string) string {
	// Hasheamos la contraseña usando SHA512
	passwordHash := sha512.Sum512([]byte(password))
	slice := passwordHash[:]
	// Codificación base64
	pass := encode64(slice)

	return pass
}

// Client Gestiona el modo cliente
func Client() {
	/* Creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas) */
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	var user User
	var regUser User
	var command string
	var checked bool

	// Mientras no elija salir
	for command != "exit" {

		if command != "register" {
			if checked {
				fmt.Printf("Options: | list | upload | download | logout | exit |")
			} else {
				fmt.Printf("Options: | login | register | exit |")
			}
		}

		if command != "register" {
			fmt.Printf("\nCommand: ")
			fmt.Scanf("%s\n", &command)
		} else {
			command = "register"
		}

		switch command {
		// Autenticacion
		case "login":
			fmt.Printf("Username: ")
			fmt.Scanf("%s\n", &user.Name)

			fmt.Printf("Password: ")
			fmt.Scanf("%s\n", &user.Password)

			// Hasheamos contraseña
			password := hashPass(user.Password)

			// Estructura con los valores a enviar en la peticion POST
			data := url.Values{}
			data.Set("username", user.Name)
			data.Set("password", password) // password (string) con hash y base64

			// Registro POST
			r, err := client.PostForm("https://localhost:10443/login", data)
			chk(err)

			message, _ := ioutil.ReadAll(r.Body)
			var respuesta resp

			json.Unmarshal(message, &respuesta)

			if respuesta.Ok {
				checked = true
			} else {
				checked = false
			}
			fmt.Println(respuesta.Msg)

			// r.Header.Get("Status") para coger campos del header

		// Registrar usuario
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

			// Registro POST
			r, err := client.PostForm("https://localhost:10443/register", data)
			chk(err)
			io.Copy(os.Stdout, r.Body)

			// Reseteamos comando
			command = ""
		// Mostrar lista de ficheros del usuario
		case "list":
			r, err := client.Get("https://localhost:10443/list?user=" + user.Name)
			chk(err)
			//io.Copy(os.Stdout, r.Body)

			bodyBytes, err := ioutil.ReadAll(r.Body)
			chk(err)

			var ficheros Files

			error := json.Unmarshal(bodyBytes, &ficheros)
			chk(error)

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

			// Elegir archivo a subir
			fmt.Printf("Filename: ")
			fmt.Scanf("%s\n", &filename)

			data := url.Values{}
			data.Set("username", user.Name)
			data.Set("filename", filename) // password (string) con hash y base64

			// Registro POST
			r, err := client.PostForm("https://localhost:10443/upload", data)
			chk(err)
			if err != nil {
				panic(err)
			}
			io.Copy(os.Stdout, r.Body)

		case "download":
			var filename string

			// Elegir archivo a descargar
			fmt.Printf("Filename: ")
			fmt.Scanf("%s\n", &filename)

			data := url.Values{}
			data.Set("username", user.Name)
			data.Set("filename", filename) // password (string) con hash y base64

			// Registro POST
			r, err := client.PostForm("https://localhost:10443/download", data)
			chk(err)
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
