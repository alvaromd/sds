/*
Serialización (JSON) y cifrado de datos (AES-CTR)
*/

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
)

// ejemplo de tipo para un usuario
type user struct {
	Name     string // nombre de usuario
	Password string // contraseña
}

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// función para codificar de []bytes a string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// función para decodificar de string a []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

// función para cifrar (con AES en este caso), adjunta el IV al principio
func encrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16)    // reservamos espacio para el IV al principio
	rand.Read(out[:16])                 // generamos el IV
	blk, err := aes.NewCipher(key)      // cifrador en bloque (AES), usa key
	chk(err)                            // comprobamos el error
	ctr := cipher.NewCTR(blk, out[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out[16:], data)    // ciframos los datos
	return
}

// función para descifrar (con AES en este caso)
func decrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)-16)     // la salida no va a tener el IV
	blk, err := aes.NewCipher(key)       // cifrador en bloque (AES), usa key
	chk(err)                             // comprobamos el error
	ctr := cipher.NewCTR(blk, data[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out, data[16:])     // desciframos (doble cifrado) los datos
	return
}

// funcion para cargar base de datos
func loadMap(gUsers map[string]user) bool {
	raw, err := ioutil.ReadFile("./db.json")
	if err != nil {
		fmt.Println(err.Error())
		return false
	}
	json.Unmarshal(raw, &gUsers)
	return true
}

// recorremos el mapa y mostramos las entradas
func showDbEntries(gUsers map[string]user, keyData []byte) {
	fmt.Printf("User database: \n")
	for k := range gUsers {
		fmt.Printf("    %s - %s\n", gUsers[k].Name, decrypt(decode64(gUsers[k].Password), keyData)) // decodificamos y desencriptamos las contraseñas
	}
	return
}

func main() {

	var masterKey string
	gUsers := make(map[string]user)

	// la primera vez pedimos una clave maestra
	if !loadMap(gUsers) {
		fmt.Print("Enter master key (first time): ")
	} else {
		fmt.Print("Enter master key: ")
	}
	fmt.Scanf("%s \n", &masterKey)

	// creamos usuario
	var newUser user
	fmt.Print("Enter Your login: ")
	fmt.Scanf("%s \n", &newUser.Name)

	// contraseña
	var password string
	fmt.Print("Enter Your password: ")
	fmt.Scanf("%s \n", &password)

	// encriptamos y codificamos en base64
	// generamos clave usando SHA512
	keyClient := sha512.Sum512([]byte(masterKey))
	keyData := keyClient[32:64] // una mitad para cifrar datos (256 bits)
	newUser.Password = encode64(encrypt([]byte(password), keyData))

	// Almacenamos el usuario
	gUsers[newUser.Name] = newUser

	// Serializamos el mapa
	jsonString, err := json.Marshal(gUsers)
	if err != nil {
		fmt.Println(err)
	}

	// Mostramos base de datos (desciframos contraseñas)
	showDbEntries(gUsers, keyData)

	// Guardamos el mapa serializado en formato JSON
	err = ioutil.WriteFile("./db.json", jsonString, 0644)
	chk(err)
}
