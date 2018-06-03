package main

import (
	"client"
	"fmt"
	"os"
	"server"
)

func main() {

	s := "Write srv for server and cli for client"

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "srv":
			server.Server()
		case "cli":
			client.Client()
		default:
			fmt.Println("Invalid command: '", os.Args[1], s)
		}
	} else {
		fmt.Println(s)
	}
}
