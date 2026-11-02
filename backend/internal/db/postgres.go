package db

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/arunima10a/cybersentinel/internal/auth"
	"github.com/arunima10a/cybersentinel/internal/correlation"
	"github.com/lib/pq"
)

type Database struct {
	conn *sql.DB
}

func Connect(connStr string) (*Database, error) {
	var conn *sql.DB
	var err error

	// Retry loop: wait for Postgres container to finish booting
	for i := 0; i < 10; i++ {
		conn, err = sql.Open("postgres", connStr)
		if err == nil && conn.Ping() == nil {
			fmt.Println("[+] Successfully connected to PostgreSQL database.")
			return &Database{conn: conn}, nil
		}
		time.Sleep(2 * time.Second)
	}

	return nil, fmt.Errorf("failed to connect to postgres after retries: %v", err)
}

// SaveAuditLog stores a hash-chained audit entry in PostgreSQL
func (d *Database) SaveAuditLog(entry auth.AuditLogEntry) error {
	query := `INSERT INTO audit_logs (log_index, timestamp, username, role, action, resource, status, previous_hash, current_hash)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := d.conn.Exec(query, entry.Index, entry.Timestamp, entry.Username, string(entry.Role), entry.Action, entry.Resource, entry.Status, entry.PreviousHash, entry.CurrentHash)
	return err
}

// GetAuditLogs loads all audit logs from PostgreSQL ordered by index
func (d *Database) GetAuditLogs() ([]auth.AuditLogEntry, error) {
	query := `SELECT log_index, timestamp, username, role, action, resource, status, previous_hash, current_hash FROM audit_logs ORDER BY log_index ASC`
	rows, err := d.conn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []auth.AuditLogEntry
	for rows.Next() {
		var entry auth.AuditLogEntry
		var roleStr string
		if err := rows.Scan(&entry.Index, &entry.Timestamp, &entry.Username, &roleStr, &entry.Action, &entry.Resource, &entry.Status, &entry.PreviousHash, &entry.CurrentHash); err != nil {
			continue
		}
		entry.Role = auth.Role(roleStr)
		logs = append(logs, entry)
	}
	return logs, nil
}

// SaveIncident persists a detected incident in PostgreSQL
func (d *Database) SaveIncident(inc correlation.Incident) error {
	query := `INSERT INTO incidents (incident_type, severity, confidence, description, evidence_tags)
	          VALUES ($1, $2, $3, $4, $5)`
	_, err := d.conn.Exec(query, inc.Type, inc.Severity, inc.Confidence, inc.Description, pq.Array(inc.Evidence))
	return err
}

// GetIncidents loads historical incidents from PostgreSQL
func (d *Database) GetIncidents() ([]correlation.Incident, error) {
	query := `SELECT incident_type, severity, confidence, description, evidence_tags FROM incidents ORDER BY id DESC LIMIT 50`
	rows, err := d.conn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []correlation.Incident
	for rows.Next() {
		var inc correlation.Incident
		if err := rows.Scan(&inc.Type, &inc.Severity, &inc.Confidence, &inc.Description, pq.Array(&inc.Evidence)); err != nil {
			continue
		}
		list = append(list, inc)
	}
	return list, nil
}

// SaveEvidenceRecord persists forensic metadata into PostgreSQL
func (d *Database) SaveEvidenceRecord(filename, encryptedFile, hash, signature, status string) error {
	query := `INSERT INTO evidence_records (filename, encrypted_file, sha256_hash, rsa_signature, status)
	          VALUES ($1, $2, $3, $4, $5)`
	_, err := d.conn.Exec(query, filename, encryptedFile, hash, signature, status)
	return err
}