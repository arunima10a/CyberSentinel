package main

import (
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/arunima10a/cybersentinel/internal/correlation"
	"github.com/arunima10a/cybersentinel/internal/forensics"
	"github.com/arunima10a/cybersentinel/internal/scanner"
)

type Evidence struct {
	Filename string `json:"filename"`
	Hash     string `json:"hash"`
	Status   string `json:"status"`
}

type Incident struct {
	Type       string   `json:"type"`
	Severity   string   `json:"severity"`
	Confidence int      `json:"confidence"`
	Evidence   []string `json:"evidence_tags"`
}

func enableCORS(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type")

}

var (
	platformPrivKey *rsa.PrivateKey
	latestScanLock  sync.RWMutex
	latestScan      *scanner.ParsedAssessment
)

func init() {
	var err error
	platformPrivKey, err = forensics.GenerateRSAKeys()
	if err != nil {
		fmt.Println("Key gen error: ", err)
	}

}

func main() {

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(&w)
		fmt.Fprintf(w, "CyberSentinel API is online")
	})

	http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(&w)
		target := "target-web"

		rawResult, err := scanner.RunNmapScanWithCapture(target)
		if err != nil {
			http.Error(w, "Scan failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		parsed := scanner.ParseNmapOutput(target, rawResult.Output)

		latestScanLock.Lock()
		latestScan = &parsed
		latestScanLock.Unlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(parsed)
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

	http.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(&w)

		cmd := exec.Command("python3", "/app/analysis/analyze.py")
		out, err := cmd.Output()
		if err != nil {
			http.Error(w, "PCAP analysis failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		var features correlation.TrafficFeatures
		if err := json.Unmarshal(out, &features); err != nil {
			http.Error(w, "Failed to parse analyzer output: "+err.Error(), http.StatusInternalServerError)
			return
		}

		openPorts := 0
		latestScanLock.RLock()
		if latestScan != nil {
			openPorts = len(latestScan.Services)
		}
		latestScanLock.RUnlock()

		incidents := correlation.Correlate(openPorts, features)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(incidents)
	})

	fmt.Println("Server starting on : 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}
}
