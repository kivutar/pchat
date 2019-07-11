package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
)

var messages = make(chan string)
var contact, port, i, usrDir string
var myPrivKey, contactPubKey *[32]byte
var contactCRT, contactEndpoint []byte

func main() {
	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")

	flag.StringVar(&i, "i", "id", "Use specific key pairs")
	flag.StringVar(&contact, "contact", "nobody", "Name of the person to chat with")
	flag.StringVar(&port, "port", "3000", "Port to listen for incoming messages")
	flag.Parse()

	usrDir, _ = os.UserHomeDir()
	err := os.MkdirAll(filepath.Join(usrDir, ".pchat", "contacts"), 0700)
	if err != nil {
		panic(err)
	}
	if _, err := os.Stat(filepath.Join(usrDir, ".pchat", i+".priv")); err != nil {
		fmt.Println("No keys found for " + i + ", generating keys...")
		genKeys()
		genCert("localhost")
		fmt.Println("done.")
		return
	}

	contactPubKey = mustReadKey(filepath.Join(usrDir, ".pchat", "contacts", contact, "pub"))
	myPrivKey = mustReadKey(filepath.Join(usrDir, ".pchat", i+".priv"))
	contactCRT = mustReadFile(filepath.Join(usrDir, ".pchat", "contacts", contact, "crt"))
	contactEndpoint = mustReadFile(filepath.Join(usrDir, ".pchat", "contacts", contact, "endpoint"))

	go listen()
	draw()
}

func handler(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	decrypted := decrypt(body, contactPubKey, myPrivKey)

	messages <- string(decrypted)
}

func listen() {
	http.HandleFunc("/", handler)

	err := http.ListenAndServeTLS(
		":"+port,
		filepath.Join(usrDir, ".pchat", i+".crt"),
		filepath.Join(usrDir, ".pchat", i+".key"),
		nil,
	)
	if err != nil {
		panic(err)
	}
}

func send(msg string) error {
	encrypted := encrypt([]byte(msg), contactPubKey, myPrivKey)

	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM(contactCRT)
	if !ok {
		return errors.New("failed to parse root certificate")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    pool,
			},
		},
	}

	_, err := client.Post(string(contactEndpoint), "text/plain", bytes.NewBuffer(encrypted))
	if err != nil {
		return err
	}

	return nil
}
