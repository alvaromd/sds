package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgryski/dgoogauth"
	"github.com/goinggo/tracelog"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Name         string `json:"name"`
	Password     string `json:"password"`
	Key          string `json:"key"`
	FAuth        string `json:"fauth"`
	FAuthEnabled bool   `json:"fauthenabled"`
	UserFiles    Files  `json:"files"`
}

// JwtToken struct para el token jwt
type JwtToken struct {
	Token string `json:"token"`
}

type OtpToken struct {
	Token string `json:"otp"`
}

// Exception exception for jwt token
type Exception struct {
	Message string `json:"message"`
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

// Files struct array de ficheros
type Files struct {
	Files []File `json:"files"`
}

// File struct fichero
type File struct {
	Name string    `json:"file"`
	Size int64     `json:"size"`
	Time time.Time `json:"time"`
}

// función para escribir una respuesta del servidor
func response(w io.Writer, ok bool, msg string) {
	r := resp{Ok: ok, Msg: msg}    // formateamos respuesta
	rJSON, err := json.Marshal(&r) // codificamos en JSON
	Chk(err)                       // comprobamos error
	w.Write(rJSON)                 // escribimos el JSON resultante
}

func responseFiles(w io.Writer, fichero Files) {
	rJSON, err := json.Marshal(&fichero) // codificamos en JSON
	Chk(err)                             // comprobamos error
	w.Write(rJSON)                       // escribimos el JSON resultante
}

func responseToken(w io.Writer, ok bool, msg string, token string) {
	r := respToken{Ok: ok, Msg: msg, Token: token}
	rJSON, err := json.Marshal(&r)
	Chk(err)
	w.Write(rJSON)
}

// Chk function to check errors (saves lines of code)
func Chk(e error) {
	if e != nil {
		panic(e)
	}
}

const (
	secretKey = "sds2018alvaroproject"
)

/***
SERVER
***/

//Server Gestiona el modo servidor
func Server() {
	// suscripción SIGINT
	stopChan := make(chan os.Signal)
	signal.Notify(stopChan, os.Interrupt)

	mux := http.NewServeMux()

	// Logger starts
	tracelog.StartFile(1, "log/log-server", 30)

	// Endpoints
	mux.Handle("/register", http.HandlerFunc(register))
	mux.Handle("/login", http.HandlerFunc(loginWithToken))
	mux.HandleFunc("/list", ValidateMiddleware(listUserFiles))
	mux.HandleFunc("/upload", ValidateMiddleware(uploadEndpoint))
	mux.HandleFunc("/download", ValidateMiddleware(downloadEndpoint))
	mux.HandleFunc("/delete", ValidateMiddleware(delete))

	mux.Handle("/gen-secret", http.HandlerFunc(GenerateSecret))
	mux.Handle("/2fauth", http.HandlerFunc(VerifyOtpEndpoint))
	mux.Handle("/getFauth", http.HandlerFunc(getUserFauth))

	//mux.Handle("/checkUserFA", http.HandlerFunc(checkFAEnabledEndpoint))
	mux.Handle("/enableTwoFA", http.HandlerFunc(enableTwoFAEndpoint))
	mux.Handle("/disableTwoFA", http.HandlerFunc(disableTwoFAEndpoint))

	srv := &http.Server{Addr: ":10443", Handler: mux}

	go func() {
		if err := srv.ListenAndServeTLS("cert.pem", "key.pem"); err != nil {
			log.Printf("listen: %s\n", err)
		}
	}()

	<-stopChan // Waits for SIGINT signal
	log.Println("Turning off server...")

	// Secure server turn down
	ctx, fnc := context.WithTimeout(context.Background(), 5*time.Second)
	fnc()
	srv.Shutdown(ctx)

	log.Println("Server stopped successfully")
}

/*
*	HANDLERS
 */

func ValidateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		bearerToken, err := GetBearerToken(req.Header.Get("Authorization"))

		if err != nil {
			json.NewEncoder(w).Encode(err)
			return
		}
		decodedToken, err := VerifyJwt(bearerToken, secretKey)

		if err != nil {
			json.NewEncoder(w).Encode(err)
			return
		}
		if decodedToken["authorized"] == true {
			next(w, req)
		} else {
			json.NewEncoder(w).Encode("2FA is required")
		}
	})
}

func checkFAEnabledEndpoint(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	w.Header().Set("Content-Type", "text/plain")

	var user = req.Form.Get("username")

	var enabled = checkFAEnabled(user)

	if enabled {
		response(w, true, "Two-factor auth enabled")
	} else {
		response(w, false, "Two-factor auth disabled")
	}
}

func enableTwoFAEndpoint(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	w.Header().Set("Content-Type", "text/plain")

	var user = req.Form.Get("username")

	gUsers := make(map[string]User)
	loadMap(gUsers)

	// Obtenemos usuarios
	users := readUsers()
	var userActual User

	// Obtenemos usuario actual
	for _, u := range users {
		if u.Name == user {
			userActual = u
		}
	}

	userActual.FAuthEnabled = true

	// Almacenamos el usuario
	gUsers[userActual.Name] = userActual

	// Serializamos el mapa
	jsonString, err := json.Marshal(gUsers)
	if err != nil {
		fmt.Println(err)
	}

	// Guardamos el mapa serializado en formato JSON
	err = ioutil.WriteFile("./db/db.json", jsonString, 0644)
	Chk(err)

	response(w, true, "Two-factor auth enabled")
	tracelog.Trace("server", "enableTwoFAEndpoint", "Two-factor auth enabled")
}

func disableTwoFAEndpoint(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	w.Header().Set("Content-Type", "text/plain")

	var user = req.Form.Get("username")

	gUsers := make(map[string]User)
	loadMap(gUsers)

	// Obtenemos usuarios
	users := readUsers()
	var userActual User

	// Obtenemos usuario actual
	for _, u := range users {
		if u.Name == user {
			userActual = u
		}
	}

	userActual.FAuthEnabled = false

	// Almacenamos el usuario
	gUsers[userActual.Name] = userActual

	// Serializamos el mapa
	jsonString, err := json.Marshal(gUsers)
	if err != nil {
		fmt.Println(err)
	}

	// Guardamos el mapa serializado en formato JSON
	err = ioutil.WriteFile("./db/db.json", jsonString, 0644)
	Chk(err)

	response(w, userActual.FAuthEnabled, "Two-factor auth disabled")
	tracelog.Trace("server", "disableTwoFAEndpoint", "Two-factor auth disabled")
}

func getUserFauth(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	w.Header().Set("Content-Type", "text/plain")

	var user = req.Form.Get("username")

	users := make(map[string]User)

	raw, err := ioutil.ReadFile("./db/db.json")
	if err != nil {
		fmt.Println(err.Error())
	}
	json.Unmarshal(raw, &users)

	resp := "Error getting user key"

	for us := range users {
		var name = users[us].Name
		if name == user {
			resp = users[us].FAuth
		}
	}

	response(w, true, resp)
}

func GetBearerToken(header string) (string, error) {
	if header == "" {
		return "", fmt.Errorf("An authorization header is required")
	}
	token := strings.Split(header, " ")
	if len(token) != 2 {
		return "", fmt.Errorf("Malformed bearer token")
	}
	return token[1], nil
}

func VerifyOtpEndpoint(w http.ResponseWriter, req *http.Request) {
	var secret = req.Header.Get("secret")
	var otpToken = req.Header.Get("otpToken")

	bearerToken, err := GetBearerToken(req.Header.Get("Authorization"))

	decodedToken, err := VerifyJwt(bearerToken, secretKey)
	if err != nil {
		json.NewEncoder(w).Encode(err)
		return
	}
	otpc := &dgoogauth.OTPConfig{
		Secret:      secret,
		WindowSize:  3,
		HotpCounter: 0,
	}

	decodedToken["authorized"], _ = otpc.Authenticate(otpToken)
	if decodedToken["authorized"] == false {
		json.NewEncoder(w).Encode("Invalid one-time password")
		return
	}
	jwToken, _ := SignJwt(decodedToken, secretKey)

	//json.NewEncoder(w).Encode(jwToken)
	responseToken(w, true, "Token generated", jwToken)
}

func SignJwt(claims jwt.MapClaims, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func VerifyJwt(token string, secret string) (map[string]interface{}, error) {
	jwToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	if !jwToken.Valid {
		return nil, fmt.Errorf("Invalid authorization token")
	}
	return jwToken.Claims.(jwt.MapClaims), nil
}

func GenerateSecret(w http.ResponseWriter, req *http.Request) {
	random := make([]byte, 10)
	rand.Read(random)
	secret := base32.StdEncoding.EncodeToString(random)
	json.NewEncoder(w).Encode(secret)
}

func loginWithToken(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	w.Header().Set("Content-Type", "text/plain")

	var user User
	_ = json.NewDecoder(req.Body).Decode(&user)

	user.Name = req.Form.Get("username")
	user.Password = req.Form.Get("password")

	if checkIfExists(user.Name) == true {
		if checkPassword(user.Name, user.Password) {
			mockUser := make(map[string]interface{})
			mockUser["username"] = user.Name
			mockUser["password"] = user.Password

			//faEnabled := checkFAEnabled(user.Name)

			mockUser["authorized"] = true

			tokenString, err := SignJwt(mockUser, secretKey)
			if err != nil {
				json.NewEncoder(w).Encode(err)
				return
			}

			tracelog.Trace("server", "createTokenEndpoint", "Token created")
			responseToken(w, true, "Login successful", tokenString)

		} else {
			tracelog.Trace("server", "createTokenEndpoint", "Wrong password")
			response(w, false, "Wrong password")
		}
	} else {
		tracelog.Trace("server", "createTokenEndpoint", "Wrong username")
		response(w, false, "Wrong username")
	}
}

func register(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	var user = req.Form.Get("username")
	var pass = req.Form.Get("password")
	var fauth = req.Form.Get("fauth")

	saveUser(user, pass, fauth)

	w.Write([]byte("Registered successfully"))
	tracelog.Trace("server", "register", "User "+user+" registered")
}

// Autenticacion
func login(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	var user User

	user.Name = req.Form.Get("username")
	user.Password = req.Form.Get("password")

	if checkIfExists(user.Name) == true {
		if checkPassword(user.Name, user.Password) {
			tracelog.Trace("server", "login", "User "+user.Name+" logged in")
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
func listUserFiles(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	fmt.Println("-- FILES --")

	user := req.URL.Query().Get("user")

	files := listFiles(user)

	for i := range files.Files {
		fmt.Print("Name: ")
		fmt.Println(files.Files[i].Name)
		fmt.Print(" - Size: ")
		fmt.Println(files.Files[i].Size)
		fmt.Print(" - Time: ")
		fmt.Println(files.Files[i].Time)
	}

	//ficheros, _ := json.Marshal(files)
	//w.Write(ficheros)

	responseFiles(w, files)
	tracelog.Trace("server", "listUserFiles", "Files of "+user+" listed")
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
	Chk(err)

	tracelog.Trace("server", "addFileToBD", "File "+file.Name+" added to db")
}

func deleteFileFromBD(userFiles Files, filename string, user string) {
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

	// Creamos nuevo array que guardaremos sin el fichero borrado
	var files Files
	//var numFiles = len(userActual.UserFiles.Files) - 1 // Restamos el elemento que vamos a borrar

	// Mientras el nombre sea diferente, vamos añadiendo ficheros a la bd
	for _, f := range userActual.UserFiles.Files {
		if f.Name != filename {
			files.Files = append(files.Files, f)
		}
	}

	// Guardamos en el usuario el nuevo slice
	userActual.UserFiles.Files = files.Files

	// Almacenamos el usuario
	gUsers[userActual.Name] = userActual

	// Serializamos el mapa
	jsonString, err := json.Marshal(gUsers)
	if err != nil {
		fmt.Println(err)
	}

	// Guardamos el mapa serializado en formato JSON
	err = ioutil.WriteFile("./db/db.json", jsonString, 0644)
	Chk(err)

	tracelog.Trace("server", "deleteFileFromBD", "File "+filename+" deleted from db")
}

// Funcion para subir archivo
func uploadEndpoint(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	w.Header().Set("Content-Type", "text/plain")

	var user = req.Header.Get("username")
	var filename = req.Header.Get("filename")

	var validFilename = false

	filesToUpload := listFilesToUpload(user)

	for _, f := range filesToUpload.Files {
		if filename == f.Name {
			validFilename = true
		}
	}

	if validFilename {
		// Leemos el archivo indicado
		file, err := ioutil.ReadFile("./client/filesToUpload/" + filename)
		Chk(err)

		// Obtenemos la key del usuario y la usamos para cifrar el fichero
		keyData := decode64(getUserKey(user))
		fichero := encrypt(file, keyData)

		// Creamos el fichero con sus datos
		var archivoAñadir = File{Name: filename, Size: int64(len(file)), Time: time.Now()}

		err = ioutil.WriteFile("./files/"+user+"/"+filename, fichero, 0644)
		if err == nil {
			fmt.Println("File " + filename + " uploaded")
		} else {
			fmt.Println(err)
		}

		// Guardamos la info del fichero en BD
		addFileToBD(archivoAñadir, user)

		response(w, true, "File "+filename+" uploaded")
		tracelog.Trace("server", "upload", "File "+filename+" uploaded to db")

	} else {
		response(w, false, "The file does not exist")
		tracelog.Trace("server", "upload", "Error getting file")
	}

}

// Funcion para subir archivo
func downloadEndpoint(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	var user = req.Header.Get("username")
	var filename = req.Header.Get("filename")

	var validFilename = false

	filesToUpload := listFiles(user)

	for _, f := range filesToUpload.Files {
		if filename == f.Name {
			validFilename = true
		}
	}

	if validFilename {
		// Leemos el archivo indicado, por ahora en la misma ruta que el proyecto
		file, err := ioutil.ReadFile("./files/" + user + "/" + filename)
		Chk(err)

		// Obtenemos la key del usuario y la usamos para descifrar el fichero
		keyData := decode64(getUserKey(user))
		fichero := decrypt(file, keyData)

		currentTime := time.Now().Local()

		err = ioutil.WriteFile("./downloads/"+currentTime.Format("2006-01-02")+"_"+filename, fichero, 0644)
		if err == nil {
			fmt.Println("File " + filename + " downloaded")
		} else {
			fmt.Println(err)
		}

		response(w, true, "File "+filename+" downloaded")
		tracelog.Trace("server", "download", "File "+filename+" downloaded")
	} else {
		response(w, false, "The file does not exist")
		tracelog.Trace("server", "download", "Error getting file")
	}

}

func delete(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	var user = req.Header.Get("username")
	var filename = req.Header.Get("filename")

	var validFilename = false

	filesToUpload := listFiles(user)

	for _, f := range filesToUpload.Files {
		if filename == f.Name {
			validFilename = true
		}
	}

	if validFilename {
		err := os.Remove("./files/" + user + "/" + filename)
		Chk(err)

		userFiles := listFiles(user)

		deleteFileFromBD(userFiles, filename, user)

		response(w, true, "File "+filename+" deleted")
		tracelog.Trace("server", "delete", "File "+filename+" deleted")
	} else {
		response(w, false, "The file does not exist")
		tracelog.Trace("server", "delete", "Error getting file")
	}

}

/*
*	FUNCTIONS
 */

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
func saveUser(username string, password string, fauth string) {

	gUsers := make(map[string]User)

	loadMap(gUsers)

	var newUser User
	newUser.Name = username
	newUser.FAuth = fauth
	newUser.FAuthEnabled = false

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
	Chk(err)

	tracelog.Trace("server", "saveUser", "User "+username+" saved")
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

	users := make(map[string]User)

	var userFiles Files

	raw, err := ioutil.ReadFile("./db/db.json")
	if err != nil {
		fmt.Println(err.Error())
	}
	json.Unmarshal(raw, &users)

	for us := range users {
		if users[us].Name == user {
			userFiles = users[us].UserFiles
		}
	}

	return userFiles
}

func listFilesToUpload(user string) Files {

	// Creo un mapa de ficheros
	var gFiles Files

	files, err := ioutil.ReadDir("./client/filesToUpload")
	if err != nil {
		fmt.Println(err.Error())
	}

	// Guardo la información
	for _, f := range files {
		// Creo un archivo
		var archivo = File{Name: f.Name(), Size: f.Size(), Time: time.Now()}

		gFiles.Files = append(gFiles.Files, archivo)
	}

	return gFiles
}

// Returns two-factor auth field from given user
func checkFAEnabled(user string) bool {
	users := make(map[string]User)

	raw, err := ioutil.ReadFile("./db/db.json")
	if err != nil {
		fmt.Println(err.Error())
	}
	json.Unmarshal(raw, &users)

	for us := range users {
		var name = users[us].Name
		if name == user {
			return users[us].FAuthEnabled
		}
	}

	// Si falla, devuelve el nombre del usuario
	return false
}
