FROM php:8.2-apache

# Copy vulnerable web application files
COPY . /var/www/html/

# Create a sensitive system flag on the server to prove RCE
RUN echo "CYBERSENTINEL{ROOT_LEVEL_RCE_EXPLOIT_CONFIRMED}" > /etc/flag.txt && \
    chmod 644 /etc/flag.txt

EXPOSE 80
