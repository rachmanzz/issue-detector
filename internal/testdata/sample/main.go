package main

import (
	"io/ioutil"
	"log"
)

// TODO: migrate this to os.CreateTemp with O_EXCL
func tempName() string {
	f, err := ioutil.TempFile("", "app")
	if err != nil {
		log.Fatal(err)
	}
	return f.Name()
}

// FIXME: move password out of source
var apiKey = "sk-live-9f8e7d6c5b4a3f2e"

func main() {
	log.Println(tempName())
	log.Println(apiKey)
}
