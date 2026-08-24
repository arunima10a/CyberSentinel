package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/arunima10a/cybersentinel/internal/scanner"
)

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "CyberSentinel API is online")
	})

	http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		target := "target-web"

		result, err := scanner.RunNmapScan(target)
		if err != nil {
			http.Error(w, "Scan failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	fmt.Println("Server starting on : 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}
}
