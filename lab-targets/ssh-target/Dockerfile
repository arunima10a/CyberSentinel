FROM alpine:latest

# Install OpenSSH server and rpcbind
RUN apk add --no-cache openssh-server rpcbind bash && \
    ssh-keygen -A && \
    adduser -D -s /bin/bash labuser && \
    echo "labuser:password123" | chpasswd && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config && \
    echo "Port 22" >> /etc/ssh/sshd_config && \
    echo "Port 2222" >> /etc/ssh/sshd_config

EXPOSE 22 111 2222

CMD ["sh", "-c", "rpcbind && exec /usr/sbin/sshd -D -e"]