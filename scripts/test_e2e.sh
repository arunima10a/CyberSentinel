#!/usr/bin/env bash
# ==============================================================================
# CyberSentinel - Automated System Verification Suite (macOS & Linux Compatible)
# ==============================================================================

set -u

API_URL="http://localhost:8080"
PASSED=0
FAILED=0

# Colors for terminal output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

assert_status() {
    local test_name="$1"
    local expected_status="$2"
    local actual_status="$3"

    if [ "$actual_status" -eq "$expected_status" ]; then
        echo -e "  [${GREEN}PASS${NC}] ${test_name} (HTTP ${actual_status})"
        PASSED=$((PASSED + 1))
    else
        echo -e "  [${RED}FAIL${NC}] ${test_name} (Expected HTTP ${expected_status}, got ${actual_status})"
        FAILED=$((FAILED + 1))
    fi
}

assert_contains() {
    local test_name="$1"
    local needle="$2"
    local haystack="$3"

    if echo "$haystack" | grep -q "$needle"; then
        echo -e "  [${GREEN}PASS${NC}] ${test_name} (Verified: '${needle}')"
        PASSED=$((PASSED + 1))
    else
        echo -e "  [${RED}FAIL${NC}] ${test_name} (Missing expected pattern: '${needle}')"
        FAILED=$((FAILED + 1))
    fi
}

# Helper to execute curl portably on macOS and Linux
do_curl() {
    local method="$1"
    local url="$2"
    local token="$3"

    local raw
    if [ -n "$token" ]; then
        raw=$(curl -s -X "$method" -w "\n%{http_code}" -H "X-Auth-Token: $token" "$url")
    else
        raw=$(curl -s -X "$method" -w "\n%{http_code}" "$url")
    fi

    # sed '$d' deletes the last line portably across macOS and Linux
    CURL_BODY=$(echo "$raw" | sed '$d')
    CURL_CODE=$(echo "$raw" | tail -n 1)
}

echo -e "\n${BLUE}==================================================================${NC}"
echo -e "${BLUE}        CYBERSENTINEL - AUTOMATED SYSTEM VERIFICATION SUITE       ${NC}"
echo -e "${BLUE}==================================================================${NC}\n"

# ------------------------------------------------------------------------------
# 1. CORE API & TARGET CHECKS
# ------------------------------------------------------------------------------
echo -e "${YELLOW}Stage 1: Core Service & Health Verification${NC}"
do_curl "GET" "${API_URL}/health" ""
assert_status "API Gateway Online" 200 "$CURL_CODE"
assert_contains "Health Response Body" "online" "$CURL_BODY"

# ------------------------------------------------------------------------------
# 2. ASSESSMENT & WEB EXPLOITATION
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}Stage 2: Security Assessment & Exploitation Verification${NC}"

# Scan Web Target
do_curl "GET" "${API_URL}/scan?target=target-web" "token_analyst_123"
assert_status "Assessment Scan (target-web)" 200 "$CURL_CODE"
assert_contains "Port 80 Discovery" "\"port\":80" "$CURL_BODY"

# Web Exploits (RCE, SQLi, LFI)
do_curl "GET" "${API_URL}/attack/web?target=target-web" "token_analyst_123"
assert_status "Web Exploit Assessment Execution" 200 "$CURL_CODE"
assert_contains "RCE Exploit Verification" "CRITICAL" "$CURL_BODY"
assert_contains "SQLi Auth Bypass Verification" "SQL Injection" "$CURL_BODY"
assert_contains "Path Traversal Verification" "passwd" "$CURL_BODY"

# ------------------------------------------------------------------------------
# 3. DYNAMIC INCIDENT CORRELATION
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}Stage 3: Traffic Feature Extraction & Dynamic Correlation${NC}"
do_curl "GET" "${API_URL}/incidents" "token_analyst_123"
assert_status "Correlation Engine Evaluation" 200 "$CURL_CODE"
assert_contains "Dynamic Reconnaissance Incident" "Active Network Reconnaissance" "$CURL_BODY"

# ------------------------------------------------------------------------------
# 4. CRYPTOGRAPHIC EVIDENCE CHAIN
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}Stage 4: Cryptographic Evidence Layer & Vault Operations${NC}"

# Seal Evidence (SHA-256 + AES-GCM + Blind Index)
do_curl "GET" "${API_URL}/protect" "token_investigator_456"
assert_status "Evidence Sealing (SHA-256 / AES-GCM)" 200 "$CURL_CODE"
assert_contains "SHA-256 Hash Generated" "\"hash\":" "$CURL_BODY"

# RSA Digital Signature
do_curl "GET" "${API_URL}/sign" "token_investigator_456"
assert_status "RSA-2048 Digital Signature Generation" 200 "$CURL_CODE"
assert_contains "Signature Authority Signer" "CyberSentinel_Root_CA" "$CURL_BODY"

# Search Encrypted Vault with Trapdoor
do_curl "GET" "${API_URL}/search?q=80" "token_investigator_456"
assert_status "Zero-Knowledge Blind Index Search" 200 "$CURL_CODE"
assert_contains "HMAC Trapdoor Token Generated" "\"trapdoor_token\":" "$CURL_BODY"
assert_contains "Encrypted PCAP Match Located" ".enc" "$CURL_BODY"

# ------------------------------------------------------------------------------
# 5. RBAC PERMISSION ENFORCEMENT MATRIX
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}Stage 5: RBAC Role Separation & Permission Matrix Checks${NC}"

# Test 1: Analyst can scan (ALLOWED)
do_curl "GET" "${API_URL}/scan?target=target-web" "token_analyst_123"
assert_status "Analyst CAN run scans" 200 "$CURL_CODE"

# Test 2: Analyst CANNOT seal evidence (FORBIDDEN)
do_curl "GET" "${API_URL}/protect" "token_analyst_123"
assert_status "Analyst CANNOT seal evidence" 403 "$CURL_CODE"

# Test 3: Investigator CAN seal evidence (ALLOWED)
do_curl "GET" "${API_URL}/protect" "token_investigator_456"
assert_status "Investigator CAN seal evidence" 200 "$CURL_CODE"

# Test 4: Investigator CANNOT run scans (FORBIDDEN)
do_curl "GET" "${API_URL}/scan?target=target-web" "token_investigator_456"
assert_status "Investigator CANNOT run scans" 403 "$CURL_CODE"

# Test 5: Auditor CAN read audit logs (ALLOWED)
do_curl "GET" "${API_URL}/audit" "token_auditor_789"
assert_status "Auditor CAN read audit logs" 200 "$CURL_CODE"

# Test 6: Auditor CANNOT run scans (FORBIDDEN)
do_curl "GET" "${API_URL}/scan?target=target-web" "token_auditor_789"
assert_status "Auditor CANNOT run scans" 403 "$CURL_CODE"

# Test 7: Admin CAN do everything (ALLOWED)
do_curl "GET" "${API_URL}/audit" "token_admin_root"
assert_status "Admin has global authority" 200 "$CURL_CODE"

# Test 8: Invalid token rejected (UNAUTHORIZED)
do_curl "GET" "${API_URL}/audit" "invalid_fake_token"
assert_status "Invalid token rejected" 401 "$CURL_CODE"

# ------------------------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}==================================================================${NC}"
echo -e "Total Tests Executed: $((PASSED + FAILED))"
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo -e "${BLUE}==================================================================${NC}"

if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}✓ ALL END-TO-END FLOWS AND SECURITY BOUNDARIES VERIFIED SUCCESSFULLY!${NC}\n"
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED.${NC}\n"
    exit 1
fi