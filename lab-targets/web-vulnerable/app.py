from flask import Flask, request, jsonify
import subprocess
import sqlite3
import os

app = Flask(__name__)

# Initialize in-memory vulnerable user database
def init_db():
    conn = sqlite3.connect('/tmp/lab.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)')
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'SuperSecretAdminPassword!', 'administrator')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'john', 'welcome123', 'analyst')")
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return "<h1>CyberSentinel Vulnerable Target (Web-01)</h1><p>Available endpoints: /api/exec, /api/login, /api/view</p>"

# VULNERABILITY 1: OS Command Injection (Remote Code Execution - RCE)
@app.route('/api/exec', methods=['GET'])
def cmd_exec():
    cmd = request.args.get('cmd', '')
    if not cmd:
        return jsonify({"error": "Missing 'cmd' parameter"}), 400
    try:
        # Deliberate vulnerability: shell=True with unvalidated user input
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
        return jsonify({"status": "executed", "output": output.decode('utf-8', errors='ignore')})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# VULNERABILITY 2: SQL Injection (SQLi Authentication Bypass)
@app.route('/api/login', methods=['POST'])
def sql_login():
    data = request.get_json(silent=True) or request.form
    username = data.get('username', '')
    password = data.get('password', '')

    conn = sqlite3.connect('/tmp/lab.db')
    cursor = conn.cursor()
    
    # Deliberate vulnerability: String formatting in raw SQL query without parameterized inputs
    query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        if user:
            return jsonify({"status": "success", "message": f"Welcome back, {user[1]}!", "role": user[2], "injected_query": query})
        return jsonify({"status": "unauthorized", "message": "Invalid credentials", "attempted_query": query}), 401
    except Exception as e:
        conn.close()
        return jsonify({"status": "sql_error", "error": str(e), "failed_query": query}), 500

# VULNERABILITY 3: Path Traversal / Local File Inclusion (LFI)
@app.route('/api/view', methods=['GET'])
def view_file():
    filepath = request.args.get('file', '')
    if not filepath:
        return jsonify({"error": "Missing 'file' parameter"}), 400
    try:
        # Deliberate vulnerability: direct file access without path sanitization
        with open(filepath, 'r') as f:
            content = f.read()
        return jsonify({"status": "success", "file": filepath, "content": content})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)