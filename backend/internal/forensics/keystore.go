package forensics

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// LoadOrCreateSecret loads a secret from disk or creates it with owner-only
// permissions. The key directory should live on persistent storage.
func LoadOrCreateSecret(path string, size int) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}

	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != size {
			return nil, fmt.Errorf("secret %s must be %d bytes", path, size)
		}
		if err := os.Chmod(path, 0600); err != nil {
			return nil, fmt.Errorf("secure secret file: %w", err)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read secret %s: %w", path, err)
	}

	key = make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate secret: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return LoadOrCreateSecret(path, size)
	}
	if err != nil {
		return nil, fmt.Errorf("create secret %s: %w", path, err)
	}
	if _, err = file.Write(key); err != nil {
		file.Close()
		os.Remove(path)
		return nil, fmt.Errorf("write secret %s: %w", path, err)
	}
	if err = file.Close(); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("close secret %s: %w", path, err)
	}
	return key, nil
}

// LoadOrCreateRSAKey keeps the signing identity stable across restarts.
func LoadOrCreateRSAKey(path string) (*rsa.PrivateKey, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}
	if data, err := os.ReadFile(path); err == nil {
		if err := os.Chmod(path, 0600); err != nil {
			return nil, fmt.Errorf("secure signing key file: %w", err)
		}
		return parsePrivateKey(path, data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read signing key: %w", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode signing key: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		return parsePrivateKey(path, data)
	}
	if err != nil {
		return nil, fmt.Errorf("create signing key: %w", err)
	}
	if _, err = file.Write(data); err != nil {
		file.Close()
		os.Remove(path)
		return nil, fmt.Errorf("write signing key: %w", err)
	}
	if err = file.Close(); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("close signing key: %w", err)
	}
	return key, nil
}

func parsePrivateKey(path string, data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("signing key %s is not valid PEM", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key %s is not RSA", path)
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("validate signing key: %w", err)
	}
	return key, nil
}
