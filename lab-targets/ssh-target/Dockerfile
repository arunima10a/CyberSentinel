FROM alpine:latest

# Install OpenSSH server
RUN apk add --no-cache openssh-server bash

# Generate host keys
RUN ssh-keygen -A

# Create a demo user 'labuser' with password 'password123'
RUN adduser -D -s /bin/bash labuser && \
    echo "labuser:password123" | chpasswd

# Configure SSH to allow password authentication and enable verbose logging
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]