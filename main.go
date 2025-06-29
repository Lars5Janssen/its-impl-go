package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"its-impl-go/utils"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

var (
	username      string
	sharedSecret  string
	sessionID     string
	sessionKey    []byte
	myNounce      string
	serverNounce  string
	serverURL     string
	loginEndPoint string
	msgEndpoint   string
	l             log.Logger
)

func main() {
	l = *log.Default()
	dataUtils := utils.InitData{
		Logger: &l,
	}
	utils.Init(dataUtils)

	getUserData()

	sendImplLogin()

	
	fmt.Println("\n\n\n\nENTERING SERVER COMMUNICATION")
	fmt.Println("PRESS CONTROLL+C OR TYPE \"quit\" to exit")
	for {sendUserMessage()}
}

func sendUserMessage() {
	msg := getUserMessage()

	if msg == "quit" {os.Exit(0)}

	encryptedMSG := encrypt(msg, string(sessionKey))

	newMessage := message{
		Sid:     sessionID,
		Message: toBase64(encryptedMSG),
	}

	body, err := json.Marshal(newMessage)
	utils.CheckFatal("Could not parse sending data: ", err)

	request, err := http.NewRequest(
		"POST",
		serverURL+msgEndpoint,
		bytes.NewBuffer(body),
	)
	utils.CheckFatal("Could not make request: ", err)
	request.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	response, err := client.Do(request)
	utils.CheckFatal("Could not do Request: ", err)

	// use server response
	var serverMSG message
	err = json.NewDecoder(response.Body).Decode(&serverMSG)
	utils.CheckFatal("ERROR decoding server resp msg: ", err)
	
	if serverMSG.Sid != sessionID {
		l.Fatal("Server SID and Client SID do not match after server responded: SERVER SID:", serverMSG.Sid)
	}

	serverMessage := decrypt(
		string(fromBase64(serverMSG.Message)), 
		string(sessionKey))
	fmt.Println("SERVER RESPONDED:\n", serverMessage)
}

func getUserMessage() string {
	fmt.Print("Enter your message:")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	err := scanner.Err()
	utils.CheckFatal("ERROR during getUserMessage: ", err)
	return scanner.Text()
}

func getUserData() {
	serverURL = "http://localhost:8080"
	msgEndpoint = "/app/impl/msg"
	loginEndPoint = "/app/impl/sendLogin"
	username = "userTEST"
	sharedSecret = "passphrasewhichneedstobe32bytes!"

	fmt.Println("Enter y to customize config")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	err := scanner.Err()
	utils.CheckFatal("ERROR during get user input skip: ", err)
	if scanner.Text() == "y" {

		fmt.Println("SERVER CONFIGURATION")
		serverURL = getUserInput("server url", serverURL)
		msgEndpoint = getUserInput("msg endpoint", msgEndpoint)
		loginEndPoint = getUserInput("login endpoint", loginEndPoint)
		fmt.Println("\n\n\nUSER CONFIGURATION")
		username = getUserInput("username", username)
		sharedSecret = getUserInput("shared secret", sharedSecret)
		var bashse []byte
		bashse = []byte(sharedSecret)

		if len(bashse) != 32 {
			panic("Your shared secret needs to be 32 bit long")
		}
		fmt.Println("CONFIGURATION COMPLETED\n\n\n")

	}
}

func getUserInput(prompt string, defaultValue string) string {
	fmt.Println("Enter " + prompt + ": (default \"" + defaultValue + "\" )")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	err := scanner.Err()
	utils.CheckFatal("ERROR during "+prompt+" input: ", err)
	if scanner.Text() != "" {
		return scanner.Text()
	}
	return defaultValue
}

type sendImplLoginData struct {
	Username      string `json:"username"`
	EncryptedData string `json:"encryptedData"`
}

type serverResponse struct {
	ClientNounce string `json:"clientNounce"`
	ServerNounce string `json:"serverNounce"`
	Sid          string `json:"sid"`
	Sessionkey   []byte `json:"sessionkey"`
}

type message struct {
	Sid     string `json:"sid"`
	Message string `json:"ecryptedData"`
}

func sendImplLogin() {
	myNounce := strconv.FormatInt(time.Now().UnixNano(), 10)

	encryptedData := encrypt(myNounce, sharedSecret)

	sendingData := sendImplLoginData{
		Username:      username,
		EncryptedData: toBase64(encryptedData),
	}
	body, err := json.Marshal(sendingData)
	utils.CheckFatal("Could not parse sending data: ", err)

	request, err := http.NewRequest(
		"POST",
		serverURL+"/app/impl/sendLogin",
		bytes.NewBuffer(body),
	)
	utils.CheckFatal("Could not make new http request", err)
	request.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	response, err := client.Do(request)
	utils.CheckFatal("Could not do Request", err)
	// l.Println("Sending Data to Server: ",
		// "\nUsername: ", username,
		// "\nData: ", myNounce,
		// "\nencData: ", encryptedData,
		// "\nbase64Data: ", sendingData.EncryptedData,
		// "\nBody: ", string(body),
		// "\nResponse:\n", response)
	// fmt.Printf("\n\n")

	// Handeling Server Response
	var sResponse serverResponse

	responseBody, err := io.ReadAll(response.Body)
	decryptedResponse := decrypt(string(fromBase64(string(responseBody))), sharedSecret)
	l.Println(decryptedResponse)
	utils.CheckFatal("ERROR during resp body parsing: ", err)
	// err = json.NewDecoder(decryptedResponse).Decode(&sResponse)

	json.Unmarshal([]byte(decryptedResponse), &sResponse)

	l.Println("Server Response: ", sResponse)
	serverNounce = sResponse.ServerNounce
	sessionID = sResponse.Sid
	sessionKey = sResponse.Sessionkey
}

func fromBase64(input string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(input)
	utils.Check("ERROR in Decoding String: fromBase64: ", err)
	return decoded
}

func toBase64(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}

func encrypt(input string, secret string) string {
	key := []byte(secret)
	plaintext := []byte(input)

	// PKCS Padding
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	plaintext = append(plaintext, padtext...)

	block, err := aes.NewCipher(key)
	utils.Check("ERROR during new cipher encryption: ", err)

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		utils.Check("ERROR during IV generation: ", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return hex.EncodeToString(ciphertext)
}

func decrypt(input string, secret string) string {
	key := []byte(secret)
	ciphertext, err := hex.DecodeString(input)
	utils.Check("Decrypt: hex decode failed: ", err)

	block, err := aes.NewCipher(key)
	utils.Check("Decrypt: NewCipher failed: ", err)

	if len(ciphertext) < aes.BlockSize {
		l.Fatal("Decrypt: ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		l.Fatal("Decrypt: ciphertext not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Remove padding
	padding := int(ciphertext[len(ciphertext)-1])
	return string(ciphertext[:len(ciphertext)-padding])
}
