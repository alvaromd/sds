package functions

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"golang.org/x/crypto/bcrypt"
)

//Chk función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// respuesta del servidor
type resp struct {
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
}

type file struct {
	Name string
	Size int64
}

// función para escribir una respuesta del servidor
func response(w io.Writer, ok bool, msg string) {
	r := resp{Ok: ok, Msg: msg}    // formateamos respuesta
	rJSON, err := json.Marshal(&r) // codificamos en JSON
	chk(err)                       // comprobamos error
	w.Write(rJSON)                 // escribimos el JSON resultante
}

func responseFiles(w io.Writer, fichero map[int]file) {
	rJSON, err := json.Marshal(&fichero) // codificamos en JSON
	chk(err)                             // comprobamos error
	w.Write(rJSON)                       // escribimos el JSON resultante
}

/***
SERVIDOR
***/

//Server Gestiona el modo servidor
func Server() {
	// suscripción SIGINT
	stopChan := make(chan os.Signal)
	signal.Notify(stopChan, os.Interrupt)

	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(handler))

	srv := &http.Server{Addr: ":10443", Handler: mux}

	go func() {
		if err := srv.ListenAndServeTLS("cert.pem", "key.pem"); err != nil {
			log.Printf("listen: %s\n", err)
		}
	}()

	<-stopChan // espera señal SIGINT
	log.Println("Apagando servidor ...")

	// apagar servidor de forma segura
	ctx, fnc := context.WithTimeout(context.Background(), 5*time.Second)
	fnc()
	srv.Shutdown(ctx)

	log.Println("Servidor detenido correctamente")
}

func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	var user = req.Form.Get("username")
	var pass = req.Form.Get("password")

	switch req.Form.Get("cmd") { // comprobamos comando desde el cliente
	case "hola": // ** registro
		response(w, true, "Hola "+req.Form.Get("mensaje"))
	case "save":
		saveUser(user, pass)
	case "logout":
		fmt.Println("Desconectando...")
		break
	case "read":
		readUsers()
	case "list":
		files := listFiles(user)

		responseFiles(w, files)

		//uploadFiles(user)
	case "exit":
		fmt.Println("Saliendo...")
		break
	default:
		response(w, false, "Comando inválido")
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

// Funcion para cargar base de datos
func loadMap(gUsers map[string]User) bool {
	raw, err := ioutil.ReadFile("./db/db.json")
	if err != nil {
		fmt.Println(err.Error())
		return false
	}
	json.Unmarshal(raw, &gUsers)
	return true
}

func (u User) toString() string {
	bytes, err := json.Marshal(u)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	return string(bytes)
}

// readUsers Funcion para leer los usuarios desde el archivo db.json
func readUsers() {
	users := make(map[string]User)
	raw, err := ioutil.ReadFile("./db/db.json")
	if err != nil {
		fmt.Println(err.Error())
	}
	json.Unmarshal(raw, &users)

	for _, us := range users {
		fmt.Println(us.toString())
	}
}

// saveUser Guarda el usuario y la contraseña cifrados
func saveUser(username string, password string) {

	var masterKey string
	gUsers := make(map[string]User)

	// la primera vez pedimos una clave maestra
	if !loadMap(gUsers) {
		fmt.Print("Enter master key (first time): ")
	} else {
		fmt.Print("Enter master key: ")
	}
	fmt.Scanf("%s \n", &masterKey)

	var newUser User
	newUser.Name = username

	// Hash en servidor con Bcrypt
	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	// Guardo hash como pass del objeto User
	newUser.Password = encode64(passHash)

	// Almacenamos el usuario
	gUsers[newUser.Name] = newUser

	// Serializamos el mapa
	jsonString, err := json.Marshal(gUsers)
	if err != nil {
		fmt.Println(err)
	}

	// Creamos carpeta donde el usuario subira sus ficheros
	os.Mkdir("./files/"+username, 0777)

	// Guardamos el mapa serializado en formato JSON
	err = ioutil.WriteFile("./db/db.json", jsonString, 0644)
	chk(err)
}

// CheckIfExists Comprueba si el usuario ya existe en la bbdd
func CheckIfExists(user string) bool {
	users := make(map[string]User)

	raw, err := ioutil.ReadFile("./db/db.json")
	if err != nil {
		fmt.Println(err.Error())
	}
	json.Unmarshal(raw, &users)

	for us := range users {
		var name = users[us].Name
		if name == user {
			return true
		}
	}

	return false
}

// CheckPassword comprueba si la contraseña es correcta
func CheckPassword(user string, password string) bool {

	var correct = false
	users := make(map[string]User)

	raw, err := ioutil.ReadFile("./db/db.json")
	if err != nil {
		fmt.Println(err.Error())
	}

	json.Unmarshal(raw, &users)

	for us := range users {
		var name = users[us].Name

		if name == user {
			if bcrypt.CompareHashAndPassword(decode64(users[us].Password), []byte(password)) == nil {
				correct = true
			}
		}
	}

	return correct
}

func listFiles(user string) map[int]file {

	// Creo un mapa de ficheros
	gFiles := make(map[int]file)

	files, err := ioutil.ReadDir("./files/" + user)
	if err != nil {
		fmt.Println(err.Error())
	}

	// Guardo la información
	for i, f := range files {

		// Creo un archivo
		var archivo = file{Name: f.Name(), Size: f.Size()}
		gFiles[i] = archivo
	}

	fmt.Println(gFiles)

	return gFiles
}

func uploadFiles(user string) bool {

	return false
}
