/*

Este programa muestra comunicarse entre cliente y servidor,
así como el uso de HTTPS (HTTP sobre TLS) mediante certificados (autofirmados).

Conceptos: JSON, TLS

*/

package functions

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

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

	var username string
	var password string
	var command string

	fmt.Printf("Username: ")
	fmt.Scanf("%s\n", &username)

	fmt.Printf("Password: ")
	fmt.Scanf("%s\n", &password)

	fmt.Printf("Command: ")
	fmt.Scanf("%s\n", &command)

	// ** ejemplo de registro
	data := url.Values{}          // estructura para contener los valores
	data.Set("cmd", command)      // comando (string)
	data.Set("usuario", username) // usuario (string)

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	Chk(err)
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	fmt.Println()
}
