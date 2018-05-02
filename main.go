package main

import (
	"fmt"
	"functions"
	"os"
)

func main() {

	s := "Introduce srv para funcionalidad de servidor y cli para funcionalidad de cliente"

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "srv":
			fmt.Println("Entrando en modo servidor...")
			functions.Server()
		case "cli":
			fmt.Println("Entrando en modo cliente...")
			functions.Client()
		default:
			fmt.Println("Parámetro '", os.Args[1], "' desconocido. ", s)
		}
	} else {
		fmt.Println(s)
	}
}
