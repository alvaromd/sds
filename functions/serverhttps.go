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

	"github.com/goinggo/tracelog"
	"golang.org/x/crypto/bcrypt"
)

//User struct del usuario
type User struct {
	Name      string `json:"name"`
	Password  string `json:"password"`
	Key       string `json:"key"`
	UserFiles Files  `json:"files"`
}

//Chk función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// Respuesta del servidor
type resp struct {
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
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

// función para escribir una respuesta del servidor
func response(w io.Writer, ok bool, msg string) {
	r := resp{Ok: ok, Msg: msg}    // formateamos respuesta
	rJSON, err := json.Marshal(&r) // codificamos en JSON
	chk(err)                       // comprobamos error
	w.Write(rJSON)                 // escribimos el JSON resultante
}

func responseFiles(w io.Writer, fichero map[int]File) {
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

	// Iniciamos el logger
	tracelog.StartFile(1, "log/log-server", 30)

	// Endpoints de la aplicacion
	mux.Handle("/register", http.HandlerFunc(register))
	mux.Handle("/login", http.HandlerFunc(login))
	mux.Handle("/list", http.HandlerFunc(list))
	mux.Handle("/upload", http.HandlerFunc(upload))
	mux.Handle("/download", http.HandlerFunc(download))

	srv := &http.Server{Addr: ":10443", Handler: mux}

	go func() {
		if err := srv.ListenAndServeTLS("cert.pem", "key.pem"); err != nil {
			log.Printf("listen: %s\n", err)
		}
	}()

	<-stopChan // espera señal SIGINT
	log.Println("Turning off server...")

	// apagar servidor de forma segura
	ctx, fnc := context.WithTimeout(context.Background(), 5*time.Second)
	fnc()
	srv.Shutdown(ctx)

	log.Println("Server stopped successfully")
}

/*
*	MANEJADORES
 */
func register(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	var user = req.Form.Get("username")
	var pass = req.Form.Get("password")

	saveUser(user, pass)

	w.Write([]byte("Registered successfully"))
}

// Autenticacion
func login(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	var user = req.Form.Get("username")
	var pass = req.Form.Get("password")

	// Comprobamos si está registrado. Si lo está accedemos, si no le ofrecemos registrarse
	if checkIfExists(user) == true {
		// Comprobar contraseña
		if checkPassword(user, pass) {
			tracelog.Trace("server", "login", "Successful login")
			response(w, true, "Successful login")
		} else {
			tracelog.Trace("server", "login", "Wrong password")
			response(w, false, "Wrong password")
		}
	} else {
		tracelog.Trace("server", "login", "Wrong username")
		response(w, false, "Wrong username")
	}

}

// Lista de archivos del usuario y actualiza el usuario en bd
func list(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	fmt.Println("LISTING FILES")

	user := req.URL.Query().Get("user")

	files := listFiles(user)

	for i := range files.Files {
		fmt.Print("Name: ")
		fmt.Println(files.Files[i].Name)
		fmt.Print(" - ID: ")
		fmt.Println(files.Files[i].ID)
		fmt.Print(" - Size: ")
		fmt.Println(files.Files[i].Size)
		fmt.Print(" - Time: ")
		fmt.Println(files.Files[i].Time)
	}

	ficheros, _ := json.Marshal(files)

	w.Write(ficheros)
}

// Funcion auxiliar para añadir la info de un fichero a la bd
func addFileToBD(file File, user string) {
	gUsers := make(map[string]User)
	loadMap(gUsers)

	// Obtenemos usuarios
	users := readUsers()
	var userActual User

	// Obtenemos usuario actual y guardamos los ficheros
	for _, u := range users {
		if u.Name == user {
			userActual = u
		}
	}

	userActual.UserFiles.Files = append(userActual.UserFiles.Files, file)

	// Almacenamos el usuario
	gUsers[userActual.Name] = userActual

	// Serializamos el mapa
	jsonString, err := json.Marshal(gUsers)
	if err != nil {
		fmt.Println(err)
	}

	// Guardamos el mapa serializado en formato JSON
	err = ioutil.WriteFile("./db/db.json", jsonString, 0644)
	chk(err)
}

// Funcion para subir archivo
func upload(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	var user = req.Form.Get("username")
	var filename = req.Form.Get("filename")

	// Leemos el archivo indicado, por ahora en la misma ruta que el proyecto
	file, err := ioutil.ReadFile("./" + filename)
	chk(err)

	// Contamos archivos actuales en bd y guardamos contador
	files := listFiles(user)
	contador := len(files.Files)

	// Encriptamos el fichero
	//keyClient := sha512.Sum512([]byte(filename))
	//keyData := keyClient[32:64] // una mitad para cifrar datos (256 bits)

	// Obtenemos la key del usuario y la usamos para cifrar el fichero
	keyData := decode64(getUserKey(user))
	fichero := encrypt(file, keyData)

	// Creamos el fichero a añadir para ponerle id y timestamp
	var archivoAñadir = File{ID: contador + 1, Name: filename, Size: int64(len(file)), Time: time.Now()}

	err = ioutil.WriteFile("./files/"+user+"/"+filename, fichero, 0644)
	if err == nil {
		fmt.Println("File " + filename + " uploaded")
	} else {
		fmt.Println(err)
	}

	// Guardamos la info del fichero en BD
	addFileToBD(archivoAñadir, user)
}

// Funcion para subir archivo
func download(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	var user = req.Form.Get("username")
	var filename = req.Form.Get("filename")

	// Leemos el archivo indicado, por ahora en la misma ruta que el proyecto
	file, err := ioutil.ReadFile("./files/" + user + "/" + filename)
	chk(err)

	// Obtenemos la key del usuario y la usamos para descifrar el fichero
	keyData := decode64(getUserKey(user))
	fichero := decrypt(file, keyData)

	err = ioutil.WriteFile("./downloads/Descarga_"+filename, fichero, 0644)
	if err == nil {
		fmt.Println("File " + filename + " downloaded")
	} else {
		fmt.Println(err)
	}
}

/*
*	FUNCIONES
 */

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

// Cifrar (con AES en este caso), adjunta el IV al principio
func encrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16)    // reservamos espacio para el IV al principio
	rand.Read(out[:16])                 // generamos el IV
	blk, err := aes.NewCipher(key)      // cifrador en bloque (AES), usa key
	chk(err)                            // comprobamos el error
	ctr := cipher.NewCTR(blk, out[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out[16:], data)    // ciframos los datos
	return
}

// Descifrar (con AES en este caso)
func decrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)-16)     // la salida no va a tener el IV
	blk, err := aes.NewCipher(key)       // cifrador en bloque (AES), usa key
	chk(err)                             // comprobamos el error
	ctr := cipher.NewCTR(blk, data[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out, data[16:])     // desciframos (doble cifrado) los datos
	return
}

// Cargar base de datos
func loadMap(gUsers map[string]User) bool {
	raw, err := ioutil.ReadFile("./db/db.json")
	if err != nil {
		fmt.Println(err.Error())
		return false
	}
	json.Unmarshal(raw, &gUsers)
	return true
}

// Lee los usuarios desde el archivo db.json. Devuelve mapa de usuarios
func readUsers() map[string]User {
	users := make(map[string]User)
	raw, err := ioutil.ReadFile("./db/db.json")
	if err != nil {
		fmt.Println(err.Error())
	}
	json.Unmarshal(raw, &users)
	return users
}

// Guarda el usuario y la contraseña cifrados
func saveUser(username string, password string) {

	gUsers := make(map[string]User)

	//var masterKey string
	// la primera vez pedimos una clave maestra
	/*
		if !loadMap(gUsers) {
			fmt.Print("Enter master key (first time): ")
		} else {
			fmt.Print("Enter master key: ")
		}
		fmt.Scanf("%s \n", &masterKey)
	*/

	loadMap(gUsers)

	var newUser User
	newUser.Name = username

	// Hash en servidor con Bcrypt
	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	// Guardo hash como pass del objeto User
	newUser.Password = encode64(passHash)

	// Generamos clave aleatoria para cifrado y descifrado
	key := make([]byte, 32)

	_, err = rand.Read(key)
	if err != nil {
		panic(err)
	}

	// Guardamos la clave
	newUser.Key = encode64(key)

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

// Comprueba si el usuario ya existe en la bbdd
func checkIfExists(user string) bool {
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

// Comprueba si la contraseña es correcta
func checkPassword(user string, password string) bool {

	var correct = false
	users := make(map[string]User)

	raw, err := ioutil.ReadFile("./db/db.json")
	if err != nil {
		fmt.Println(err.Error())
	}

	json.Unmarshal(raw, &users)

	for us := range users {
		if user == users[us].Name {
			if bcrypt.CompareHashAndPassword(decode64(users[us].Password), []byte(password)) == nil {
				correct = true
			}
		}
	}

	return correct
}

// Comprueba si el usuario ya existe en la bbdd
func getUserKey(user string) string {
	users := make(map[string]User)

	raw, err := ioutil.ReadFile("./db/db.json")
	if err != nil {
		fmt.Println(err.Error())
	}
	json.Unmarshal(raw, &users)

	for us := range users {
		var name = users[us].Name
		if name == user {
			return users[us].Key
		}
	}

	// Si falla, devuelve el nombre del usuario
	return user
}

func listFiles(user string) Files {

	// Creo un mapa de ficheros
	var gFiles Files

	files, err := ioutil.ReadDir("./files/" + user)
	if err != nil {
		fmt.Println(err.Error())
	}

	// Guardo la información
	for i, f := range files {
		// Creo un archivo
		var archivo = File{ID: i, Name: f.Name(), Size: f.Size(), Time: time.Now()}

		gFiles.Files = append(gFiles.Files, archivo)
	}

	return gFiles
}
