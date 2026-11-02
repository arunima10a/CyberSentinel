FROM golang:1.25.1-alpine

RUN apk add --no-cache \
    nmap \
    nmap-nselibs \
    nmap-scripts \
    python3 \
    py3-pip \
    tshark  \
    openjdk17-jre-headless

RUN pip install --no-cache-dir pyshark pyspark pandas --break-system-packages

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN go build -o /usr/local/bin/api-gateway ./cmd

CMD ["api-gateway"]