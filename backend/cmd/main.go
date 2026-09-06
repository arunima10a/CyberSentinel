package main

import (
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/arunima10a/cybersentinel/internal/forensics"
	"github.com/arunima10a/cybersentinel/internal/scanner"
)

type Evidence struct {
	Filename string `json:"filename"`
	Hash     string `json:"hash"`
	Status   string `json:"status"`
}

func enableCORS(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
}

var platformPrivKey *rsa.PrivateKey

func init() {
	platformPrivKey, _ = forensics.GenerateRSAKeys()

}

func main() {

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(&w)
		fmt.Fprintf(w, "CyberSentinel API is online")
	})

	http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(&w)
		target := "target-web"

		result, err := scanner.RunNmapScan(target)
		if err != nil {
			http.Error(w, "Scan failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	http.HandleFunc("/protect", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(&w)
		files, _ := filepath.Glob("/app/evidence/*.pcap")
		if len(files) == 0 {
			http.Error(w, "No PCAP files found to protect", http.StatusNotFound)
			return
		}

		latestFile := files[len(files)-1]

		hash, err := forensics.CalculateHash(latestFile)
		if err != nil {
			http.Error(w, "Hashing failed", http.StatusInternalServerError)
			return
		}

		key := []byte("passphrasewhichneedstobe32bytes!")

		encryptedPath := latestFile + ".enc"
		err = forensics.EncryptFile(latestFile, encryptedPath, key)
		if err != nil {
			http.Error(w, "Encryption failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		evidence := Evidence{
			Filename: filepath.Base(latestFile),
			Hash:     hash,
			Status:   "Hashed and encypted",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(evidence)

	})

	http.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(&w)

		files, _ := filepath.Glob("/app/evidence/*.pcap")

		if len(files) == 0 {
			http.Error(w, "No evidence to sign", http.StatusNotFound)
			return
		}
		latestFile := files[len(files)-1]

		hashString, _ := forensics.CalculateHash(latestFile)
		hashBytes, _ := hex.DecodeString(hashString)

		signature, err := forensics.SignData(platformPrivKey, hashBytes)
		if err != nil {
			http.Error(w, "Signing failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"signature": hex.EncodeToString(signature),
			"signer":    "CyberSentinel_Root_CA",
			"status":    "Signed and Verified",
		})

	})

	fmt.Println("Server starting on : 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}
}
