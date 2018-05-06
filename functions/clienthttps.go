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

	/* creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas) */
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	var user User
	var regUser User
	var command string
	var register string
	var checked bool

	// Mientras no elija salir
	for command != "exit" {

		if command != "register" {
			if checked {
				fmt.Println("Bienvenido/a " + user.Name)
				fmt.Printf("Options: | list | logout |")
			} else {
				fmt.Printf("Options: | login | register |")
			}
		}

		if command != "register" {
			fmt.Printf("\nCommand: ")
			fmt.Scanf("%s\n", &command)
		} else {
			command = "register"
		}

		switch command {
		// LOGIN
		case "login":
			fmt.Printf("Username: ")
			fmt.Scanf("%s\n", &user.Name)

			fmt.Printf("Password: ")
			fmt.Scanf("%s\n", &user.Password)

			// Hasheamos contraseña
			password := hashPass(user.Password)

			// Comprobamos si está registrado. Si lo está accedemos, si no le ofrecemos registrarse
			if CheckIfExists(user.Name) == true {
				// Comprobar contraseña
				if CheckPassword(user.Name, password) && !checked {
					fmt.Println("Login correcto")
					checked = true
				} else {
					fmt.Println("Contraseña incorrecta")
				}
			} else {
				fmt.Println("No estás registrado, ¿deseas hacerlo? [Y] [N]")
				fmt.Scanf("%s\n", &register)

				if register == "Y" {
					command = "register"
					register = ""
				} else if register == "N" {
					fmt.Println("Saliendo del sistema")
					command = "exit"
				}
			}
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
			r, err := client.Get("https://localhost:10443/files/" + user.Name)
			chk(err)

			responseData, err := ioutil.ReadAll(r.Body)

			var responseObject []file
			json.Unmarshal(responseData, &responseObject)

			for i := 0; i < len(responseObject); i++ {
				fmt.Print("[")
				fmt.Print(i)
				fmt.Print("] - ")
				fmt.Println(responseObject[i].Name)
			}
		// Desconectar usuario
		case "logout":
			if checked {
				fmt.Printf("-- Logged out, login again --")
				fmt.Println()
				checked = false
				break
			}

		default:
			fmt.Println("Comando inválido")
		}

		fmt.Println()
	}
}
