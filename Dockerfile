# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o k8s-security-auditor .

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates python3 py3-pip

WORKDIR /root/

# Copy binary
COPY --from=builder /app/k8s-security-auditor .

# Copy Python plugin
COPY plugins/ ./plugins/

# Make binary executable
RUN chmod +x k8s-security-auditor

ENTRYPOINT ["./k8s-security-auditor"]
CMD ["--help"]
