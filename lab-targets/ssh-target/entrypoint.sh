#!/bin/bash
# CyberSentinel - Multi-Service Startup for target-ssh

# Start rpcbind (Port 111)
rpcbind

# Configure OpenSSH to listen on both Port 22 and Port 2222
echo "Port 22" >> /etc/ssh/sshd_config
echo "Port 2222" >> /etc/ssh/sshd_config

# Start SSH daemon in foreground
exec /usr/sbin/sshd -D -e