package main

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/crypto/nacl/box"
)

func encrypt(msg []byte, recipientPubKey, senderPrivKey *[32]byte) []byte {
	nonce := generateNonce()
	return box.Seal(nonce[:], msg, &nonce, recipientPubKey, senderPrivKey)
}

func decrypt(encrypted []byte, senderPubKey, recipientPrivKey *[32]byte) []byte {
	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := box.Open(nil, encrypted[24:], &decryptNonce, senderPubKey, recipientPrivKey)
	if !ok {
		panic("decryption error")
	}
	return decrypted
}

func generateNonce() [24]byte {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	return nonce
}

func mustReadKey(path string) *[32]byte {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	d, err := hex.DecodeString(string(content))
	if err != nil {
		panic(err)
	}
	var key [32]byte
	copy(key[:], d[:32])
	return &key
}

func mustReadFile(path string) []byte {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return content
}

func mustWriteKey(path string, key *[32]byte) {
	err := ioutil.WriteFile(path, []byte(hex.EncodeToString((*key)[:])), 0600)
	if err != nil {
		panic(err)
	}
}

func genKeys() {
	usrDir, _ := os.UserHomeDir()

	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	mustWriteKey(filepath.Join(usrDir, ".pchat", i+".priv"), privKey)
	mustWriteKey(filepath.Join(usrDir, ".pchat", i+".pub"), pubKey)
}
