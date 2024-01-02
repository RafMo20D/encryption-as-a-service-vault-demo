package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/hashicorp/vault/api"
)

type Vault struct {
	key []byte
}

const (
	vaultAddress = "http://localhost:8200"
	vaultToken   = "VAULT_TOKEN"
	secretPath   = "transit/keys/my-key"
)

func NewVault() (*Vault, error) {
	config := api.DefaultConfig()
	config.Address = vaultAddress
	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("error creating Vault client: %v", err)
	}

	client.SetToken(vaultToken)

	// Read the secret from Vault
	secret, err := client.Logical().Read(secretPath)
	if err != nil {
		return nil, fmt.Errorf("error reading secret from Vault: %v", err)
	}

	// Extract the encryption key from the secret
	key, ok := secret.Data["data"].(map[string]interface{})["key"].(string)
	if !ok {
		return nil, fmt.Errorf("key not found in Vault secret")
	}

	return &Vault{key: []byte(key)}, nil
}

func (v *Vault) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher block: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("error generating nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (v *Vault) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher block: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %v", err)
	}

	return plaintext, nil
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Data string `json:"data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Error decoding request: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if request.Data == "" {
		log.Println("Data cannot be empty")
		http.Error(w, "Data cannot be empty", http.StatusBadRequest)
		return
	}

	vault, err := NewVault()
	if err != nil {
		log.Printf("Error initializing Vault: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	ciphertext, err := vault.Encrypt([]byte(request.Data))
	if err != nil {
		log.Printf("Error encrypting data: %v", err)
		http.Error(w, "Encryption error", http.StatusInternalServerError)
		return
	}

	response := struct {
		Ciphertext string `json:"ciphertext"`
	}{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Ciphertext string `json:"ciphertext"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Error decoding request: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	ciphertext, err := base64.StdEncoding.DecodeString(request.Ciphertext)
	if err != nil {
		log.Printf("Error decoding ciphertext: %v", err)
		http.Error(w, "Invalid ciphertext", http.StatusBadRequest)
		return
	}

	vault, err := NewVault()
	if err != nil {
		log.Printf("Error initializing Vault: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	plaintext, err := vault.Decrypt(ciphertext)
	if err != nil {
		log.Printf("Error decrypting data: %v", err)
		http.Error(w, "Decryption error", http.StatusInternalServerError)
		return
	}

	response := struct {
		Plaintext string `json:"plaintext"`
	}{
		Plaintext: string(plaintext),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	http.HandleFunc("/encrypt", encryptHandler)
	http.HandleFunc("/decrypt", decryptHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server is running on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
