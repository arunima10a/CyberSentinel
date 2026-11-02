package forensics

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type SearchableIndex struct {
	mu        sync.RWMutex
	searchKey []byte
	index     map[string][]string
	dataPath  string
}

// LoadSearchableIndex restores the blind index from persistent storage.
func LoadSearchableIndex(key []byte, path string) (*SearchableIndex, error) {
	si := NewSearchableIndex(key)
	si.dataPath = path
	data, err := os.ReadFile(path)
	if err == nil {
		if err := os.Chmod(path, 0600); err != nil {
			return nil, fmt.Errorf("secure searchable index file: %w", err)
		}
		if err := json.Unmarshal(data, &si.index); err != nil {
			return nil, fmt.Errorf("decode searchable index: %w", err)
		}
		if si.index == nil {
			si.index = make(map[string][]string)
		}
		return si, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read searchable index: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create index directory: %w", err)
	}
	return si, nil
}

// initialize encrypted index with a dedicated search key
func NewSearchableIndex(key []byte) *SearchableIndex {
	return &SearchableIndex{
		searchKey: key,
		index:     make(map[string][]string),
	}
}

// compute the cryptographic blind index token for a keyword
func (si *SearchableIndex) GenerateTrapdoor(keyword string) string {
	normalized := strings.ToLower(strings.TrimSpace(keyword))
	h := hmac.New(sha256.New, si.searchKey)
	h.Write([]byte(normalized))
	return hex.EncodeToString(h.Sum(nil))
}

// extract and register blind tokens for an evidence file
func (si *SearchableIndex) IndexEvidence(evidenceID string, keywords []string) error {
	si.mu.Lock()
	defer si.mu.Unlock()

	updated := make(map[string][]string, len(si.index))
	for token, ids := range si.index {
		updated[token] = append([]string(nil), ids...)
	}
	for _, kw := range keywords {
		token := si.GenerateTrapdoor(kw)
		// avoid duplicate entries for same file
		exists := false
		for _, id := range updated[token] {
			if id == evidenceID {
				exists = true
				break
			}
		}
		if !exists {
			updated[token] = append(updated[token], evidenceID)
		}
	}
	if si.dataPath != "" {
		data, err := json.Marshal(updated)
		if err != nil {
			return fmt.Errorf("encode searchable index: %w", err)
		}
		tempPath := si.dataPath + ".tmp"
		if err := os.WriteFile(tempPath, data, 0600); err != nil {
			os.Remove(tempPath)
			return fmt.Errorf("write searchable index: %w", err)
		}
		if err := os.Rename(tempPath, si.dataPath); err != nil {
			os.Remove(tempPath)
			return fmt.Errorf("replace searchable index: %w", err)
		}
	}
	si.index = updated
	return nil
}

// searche index using a generated trapdoor without decrypting the dataset
func (si *SearchableIndex) Search(query string) (trapdoor string, matches []string) {
	si.mu.RLock()
	defer si.mu.RUnlock()

	trapdoor = si.GenerateTrapdoor(query)
	matches = si.index[trapdoor]
	if matches == nil {
		matches = []string{}
	}
	return trapdoor, matches
}
