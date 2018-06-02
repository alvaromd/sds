package main

import (
	"fmt"
	"functions"
	"os"
)

func main() {

	s := "Write srv for server and cli for client"

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "srv":
			functions.Server()
		case "cli":
			functions.Client()
		default:
			fmt.Println("Invalid command: '", os.Args[1], s)
		}
	} else {
		fmt.Println(s)
	}
}
