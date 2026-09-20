FROM golang:1.25.1-alpine

RUN apk update && apk add --no-cache \
    nmap \
    nmap-scripts \
    python3 \
    py3-pip \
    tshark

RUN pip install --no-cache-dir pyshark --break-system-packages

WORKDIR /app

COPY go.mod ./

RUN go mod download

COPY . .

RUN go build -o main ./cmd/main.go

EXPOSE 8080

CMD ["./main"]