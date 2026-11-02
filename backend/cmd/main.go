package main

import (
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/arunima10a/cybersentinel/internal/auth"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

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

func enableCORS(w *http.ResponseWriter, r *http.Request) bool {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Auth-Token")

	if r.Method == "OPTIONS" {
		(*w).WriteHeader(http.StatusOK)
		return true
	}
	return false

}

var (
	platformPrivKey *rsa.PrivateKey
	evidenceKey     []byte
	latestScanLock  sync.RWMutex
	latestScan      *scanner.ParsedAssessment
	encryptedIndex  *forensics.SearchableIndex
	keyDir          = envOrDefault("CYBERSENTINEL_KEY_DIR", "./secrets")
	analyzerURL     = envOrDefault("ANALYZER_URL", "http://target-web:5000")
	analyzerClient  = &http.Client{Timeout: 5 * time.Minute}
	rbacMgr         *auth.RBACManager
)

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func initializeForensics() error {
	var err error
	evidenceKey, err = forensics.LoadOrCreateSecret(filepath.Join(keyDir, "evidence-aes.key"), 32)
	if err != nil {
		return err
	}
	searchKey, err := forensics.LoadOrCreateSecret(filepath.Join(keyDir, "search-index.key"), 32)
	if err != nil {
		return err
	}
	platformPrivKey, err = forensics.LoadOrCreateRSAKey(filepath.Join(keyDir, "signing-key.pem"))
	if err != nil {
		return err
	}
	encryptedIndex, err = forensics.LoadSearchableIndex(searchKey, filepath.Join(keyDir, "search-index.json"))
	return err

}

func requireAuth(w *http.ResponseWriter, r *http.Request, action string) (auth.User, bool) {
	token := r.Header.Get("X-Auth-Token")
	if token == "" {
		rbacMgr.LogAction("anonymous", "unknown", action, r.URL.Path, "DENIED_UNAUTHENTICATED")
		http.Error(*w, "Unauthorized: Missing token", http.StatusUnauthorized)
		return auth.User{}, false
	}

	user, ok := rbacMgr.Authenticate(token)
	if !ok {
		rbacMgr.LogAction("anonymous", "unknown", action, r.URL.Path, "DENIED_UNAUTHENTICATED")
		http.Error(*w, "Unauthorized: Invalid or missing token", http.StatusUnauthorized)
		return user, false
	}

	if !rbacMgr.Authorize(user.Role, action) {
		rbacMgr.LogAction(user.Username, user.Role, action, r.URL.Path, "DENIED_FORBIDDEN")
		http.Error(*w, fmt.Sprintf("Forbidden: Role '%s' does not have permission for '%s'", user.Role, action), http.StatusForbidden)
		return user, false
	}

	rbacMgr.LogAction(user.Username, user.Role, action, r.URL.Path, "ALLOWED")
	return user, true
}

func main() {
	if err := initializeForensics(); err != nil {
		fmt.Printf("Forensics key initialization failed: %v\n", err)
		os.Exit(1)
	}
	rbacMgr = auth.NewRBACManager()

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if enableCORS(&w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "online"})
	})

	http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		if enableCORS(&w, r) {
			return
		}

		if _, ok := requireAuth(&w, r, "action:scan"); !ok {
			return
		}

		target := r.URL.Query().Get("target")
		if target == "" {
			target = "target-web"
		}
		if target != "target-web" && target != "target-ssh" {
			http.Error(w, "Unsupported scan target", http.StatusBadRequest)
			return
		}

		rawResult, err := scanner.RunTargetScan(target)
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
		if enableCORS(&w, r) {
			return
		}
		if _, ok := requireAuth(&w, r, "action:protect"); !ok {
			return
		}
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

		encryptedPath := latestFile + ".enc"
		err = forensics.EncryptFile(latestFile, encryptedPath, evidenceKey)
		if err != nil {
			http.Error(w, "Encryption failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		keywords := []string{
			"pcap",
			"target-web",
			"reconnaissance",
			"port-80",
			filepath.Base(latestFile),
		}

		latestScanLock.RLock()
		if latestScan != nil {
			keywords = append(keywords, latestScan.Target)
			for _, s := range latestScan.Services {
				keywords = append(keywords, s.Service, fmt.Sprintf("%d", s.Port))
			}
		}
		latestScanLock.RUnlock()

		// index encrypted artifact using cryptographic trapdoors
		if err := encryptedIndex.IndexEvidence(filepath.Base(encryptedPath), keywords); err != nil {
			http.Error(w, "Search index persistence failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"filename":         filepath.Base(latestFile),
			"encrypted_file":   filepath.Base(encryptedPath),
			"hash":             hash,
			"indexed_keywords": len(keywords),
			"status":           "Hashed (SHA-256), Encrypted (AES-256-GCM), and Blind-Indexed",
		})
	})

	http.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		if enableCORS(&w, r) {
			return
		}
		if _, ok := requireAuth(&w, r, "action:sign"); !ok {
			return
		}

		files, err := filepath.Glob("/app/evidence/*.pcap")
		if err != nil {
			http.Error(w, "Could not list evidence files", http.StatusInternalServerError)
			return
		}

		if len(files) == 0 {
			http.Error(w, "No evidence to sign", http.StatusNotFound)
			return
		}
		latestFile := files[len(files)-1]

		hashString, err := forensics.CalculateHash(latestFile)
		if err != nil {
			http.Error(w, "Hashing failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		hashBytes, err := hex.DecodeString(hashString)
		if err != nil {
			http.Error(w, "Could not decode evidence hash", http.StatusInternalServerError)
			return
		}
		if platformPrivKey == nil {
			http.Error(w, "Signing key is unavailable", http.StatusInternalServerError)
			return
		}

		signature, err := forensics.SignData(platformPrivKey, hashBytes)
		if err != nil {
			http.Error(w, "Signing failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"signature": hex.EncodeToString(signature),
			"signer":    "CyberSentinel_Root_CA",
			"status":    "Signed",
		})

	})

	http.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		if enableCORS(&w, r) {
			return
		}
		if _, ok := requireAuth(&w, r, "action:search"); !ok {
			return
		}

		query := r.URL.Query().Get("q")
		if query == "" {
			http.Error(w, "Query parameter 'q' is required", http.StatusBadRequest)
			return
		}

		// Compute cryptographic trapdoor and search without decrypting
		trapdoor, matches := encryptedIndex.Search(query)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"query":             query,
			"trapdoor_token":    trapdoor,
			"matches_found":     len(matches),
			"matching_evidence": matches,
		})
	})

	http.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
		if enableCORS(&w, r) {
			return
		}
		if _, ok := requireAuth(&w, r, "action:analytics"); !ok {
			return
		}

		resp, err := analyzerClient.Get(analyzerURL + "/features")
		if err != nil {
			http.Error(w, "Traffic analyzer unreachable: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			http.Error(w, fmt.Sprintf("Traffic analyzer returned HTTP %d", resp.StatusCode), http.StatusBadGateway)
			return
		}

		var features correlation.TrafficFeatures
		if err := json.NewDecoder(resp.Body).Decode(&features); err != nil {
			http.Error(w, "Failed to decode features: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if features.Error != "" {
			http.Error(w, "Traffic analysis failed: "+features.Error, http.StatusBadGateway)
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

	// PYSPARK BIG DATA ANALYTICS
	http.HandleFunc("/analytics/spark", func(w http.ResponseWriter, r *http.Request) {
		if enableCORS(&w, r) {
			return
		}
		if _, ok := requireAuth(&w, r, "action:analytics"); !ok {
			return
		}

		resp, err := analyzerClient.Get(analyzerURL + "/spark")
		if err != nil {
			http.Error(w, "Spark analyzer unreachable: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		contentType := resp.Header.Get("Content-Type")
		if contentType == "" {
			contentType = "application/json"
		}

		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})

	// 8. HASH-CHAINED AUDIT LOG TRAIL
	http.HandleFunc("/audit", func(w http.ResponseWriter, r *http.Request) {
		if enableCORS(&w, r) {
			return
		}

		if _, ok := requireAuth(&w, r, "action:audit"); !ok {
			return
		}

		logs := rbacMgr.GetAuditLogs()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logs)
	})
	http.HandleFunc("/attack/ssh", func(w http.ResponseWriter, r *http.Request) {
		if enableCORS(&w, r) {
			return
		}

		if _, ok := requireAuth(&w, r, "action:scan"); !ok {
			return
		}

		result := scanner.RunSSHBruteForce("target-ssh")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	webScanHandler := func(w http.ResponseWriter, r *http.Request) {
		if enableCORS(&w, r) {
			return
		}

		if _, ok := requireAuth(&w, r, "action:scan"); !ok {
			return
		}

		// Run automated vulnerability tests against target-web
		results := scanner.RunWebSecurityAssessment("target-web")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	}
	http.HandleFunc("/scan/web", webScanHandler)
	http.HandleFunc("/attack/web", webScanHandler) // Backward-compatible alias.

	fmt.Println("Server starting on : 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}

}
