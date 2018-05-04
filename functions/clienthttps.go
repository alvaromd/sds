package functions

import (
	"crypto/sha512"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

//Users struct que contiene un array de users
type Users struct {
	Users []User `json:"users"`
}

//User struct del usuario
type User struct {
	Name     string `json:"Name"`
	Password string `json:"Password"`
}

/***
CLIENTE
***/

// Client Gestiona el modo cliente
func Client() {

	/* creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas) */
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	var user User // struct
	var command string
	var register string
	var checked bool

	fmt.Printf("Username: ")
	fmt.Scanf("%s\n", &user.Name)

	fmt.Printf("Password: ")
	fmt.Scanf("%s\n", &user.Password)

	for command != "exit" {

		if command == "logout" {
			fmt.Printf("-- Logged out, login again --")
			fmt.Printf("\nUsername: ")
			fmt.Scanf("%s\n", &user.Name)

			fmt.Printf("Password: ")
			fmt.Scanf("%s\n", &user.Password)

			checked = false
		}

		// Hasheamos la contraseña usando SHA512
		passwordHash := sha512.Sum512([]byte(user.Password))
		slice := passwordHash[:]
		// Codificación base64
		pass := encode64(slice)

		// Comprobamos si está registrado. Si lo está accedemos, si no le ofrecemos registrarse
		if CheckIfExists(user.Name) == true {
			// Comprobar contraseña
			if CheckPassword(user.Name, pass) && !checked {
				fmt.Println("Login correcto")
				checked = true
			}
		} else {
			fmt.Println("No estás registrado, ¿deseas hacerlo? [Y] [N]")
			fmt.Scanf("%s\n", &register)
		}

		if register == "Y" {
			command = "save"
			register = ""
		} else if register == "N" {
			fmt.Println("Saliendo del sistema")
			command = "exit"
		} else {
			fmt.Printf("Options: hola | save | list | logout | exit")
			fmt.Printf("\nCommand: ")
			fmt.Scanf("%s\n", &command)
		}

		// registro
		data := url.Values{}            // estructura para contener los valores
		data.Set("cmd", command)        // comando (string)
		data.Set("username", user.Name) // usuario (string)
		data.Set("password", pass)      // password (string) con hash y base64

		r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
		chk(err)

		io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)

		fmt.Println()
	}
}
