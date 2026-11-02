package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type Role string

const (
	RoleAdmin        Role = "admin"
	RoleAnalyst      Role = "analyst"
	RoleInvestigator Role = "investigator"
	RoleAuditor      Role = "auditor"
)

type User struct {
	Username string `json:"username"`
	Role     Role   `json:"role"`
	Token    string `json:"token"`
}

type AuditLogEntry struct {
	Index        int       `json:"index"`
	Timestamp    time.Time `json:"timestamp"`
	Username     string    `json:"username"`
	Role         Role      `json:"role"`
	Action       string    `json:"action"`
	Resource     string    `json:"resource"`
	Status       string    `json:"status"`
	PreviousHash string    `json:"previous_hash"`
	CurrentHash  string    `json:"current_hash"`
}

type RBACManager struct {
	mu        sync.RWMutex
	users     map[string]User
	auditLogs []AuditLogEntry
	lastHash  string
}

func NewRBACManager() *RBACManager {
	mgr := &RBACManager{
		users:     make(map[string]User),
		auditLogs: make([]AuditLogEntry, 0),
		lastHash:  "0000000000000000000000000000000000000000000000000000000000000000",
	}

	// Pre-seed demo users for each tier
	mgr.users["token_analyst_123"] = User{Username: "analyst_alice", Role: RoleAnalyst, Token: "token_analyst_123"}
	mgr.users["token_investigator_456"] = User{Username: "investigator_bob", Role: RoleInvestigator, Token: "token_investigator_456"}
	mgr.users["token_auditor_789"] = User{Username: "auditor_clara", Role: RoleAuditor, Token: "token_auditor_789"}
	mgr.users["token_admin_root"] = User{Username: "admin_root", Role: RoleAdmin, Token: "token_admin_root"}

	return mgr
}

// Authenticate verifies the bearer token and returns the user
func (m *RBACManager) Authenticate(token string) (User, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	user, exists := m.users[token]
	return user, exists
}

// Authorize checks if a user's role has permission for an action
func (m *RBACManager) Authorize(role Role, action string) bool {
	if role == RoleAdmin {
		return true // Admin has global permissions
	}

	switch action {
	case "action:scan", "action:analytics":
		return role == RoleAnalyst
	case "action:protect", "action:sign", "action:search":
		return role == RoleInvestigator
	case "action:audit":
		return role == RoleAuditor
	default:
		return false
	}
}

// LogAction appends a cryptographically hash-chained entry to the immutable audit log
func (m *RBACManager) LogAction(username string, role Role, action, resource, status string) AuditLogEntry {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := len(m.auditLogs) + 1
	ts := time.Now().UTC()

	// Include every exposed field in the chain so edits to status are detectable.
	payload := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s", idx, ts.Format(time.RFC3339Nano), username, role, action, resource, status, m.lastHash)
	h := sha256.Sum256([]byte(payload))
	curHash := hex.EncodeToString(h[:])

	entry := AuditLogEntry{
		Index:        idx,
		Timestamp:    ts,
		Username:     username,
		Role:         role,
		Action:       action,
		Resource:     resource,
		Status:       status,
		PreviousHash: m.lastHash,
		CurrentHash:  curHash,
	}

	m.auditLogs = append(m.auditLogs, entry)
	m.lastHash = curHash

	return entry
}

func (m *RBACManager) GetAuditLogs() []AuditLogEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copied := make([]AuditLogEntry, len(m.auditLogs))
	copy(copied, m.auditLogs)
	return copied
}
