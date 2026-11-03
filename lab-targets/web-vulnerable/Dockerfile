FROM php:8.2-apache

# Install vsftpd (FTP) and sqlite3
RUN apt-get update && apt-get install -y \
    vsftpd \
    sqlite3 \
    libsqlite3-dev \
    && docker-php-ext-install pdo pdo_sqlite \
    && rm -rf /var/lib/apt/lists/*

COPY . /var/www/html/

# System flag
RUN echo "CYBERSENTINEL{ROOT_LEVEL_RCE_EXPLOIT_CONFIRMED}" > /etc/flag.txt && \
    chmod 644 /etc/flag.txt

# Configure vsftpd and Apache 8080 directly inside container
RUN mkdir -p /var/run/vsftpd/empty /var/ftp && \
    echo "CONFIDENTIAL: Internal server backup archive directory" > /var/ftp/notice.txt && \
    printf "listen=YES\nanonymous_enable=YES\nanon_root=/var/ftp\nlocal_enable=NO\nwrite_enable=NO\nconnect_from_port_20=YES\nsecure_chroot_dir=/var/run/vsftpd/empty\n" > /etc/vsftpd.conf && \
    echo "Listen 8080" >> /etc/apache2/ports.conf

EXPOSE 21 80 8080

CMD ["sh", "-c", "vsftpd /etc/vsftpd.conf & apache2-foreground"]