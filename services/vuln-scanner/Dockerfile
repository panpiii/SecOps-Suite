# Stage 1: Build stage
FROM golang:1.22-alpine AS builder

# Install build dependencies and security tools
RUN apk add --no-cache ca-certificates git make gcc libc-dev curl \
    && update-ca-certificates

# Set working directory for application
WORKDIR /app

# Create non-root user for runtime
RUN adduser -D -g '' appuser

# Copy go module files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application with security flags
# -trimpath: removes file system paths from binaries
# -ldflags="-s -w": strips debug information
# CGO_ENABLED=0: creates statically-linked binary
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -extldflags '-static'" -o /vuln-scanner ./cmd/server

# Stage 2: Install Trivy scanner
FROM alpine:3.19 AS trivy-installer

# Install Trivy vulnerability scanner
RUN apk add --no-cache curl ca-certificates \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.45.1 \
    && trivy --version

# Stage 3: Final minimal image
FROM gcr.io/distroless/static:nonroot

# Copy binary from builder stage
COPY --from=builder /vuln-scanner /vuln-scanner
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy Trivy from the trivy-installer stage
COPY --from=trivy-installer /usr/local/bin/trivy /usr/local/bin/trivy

# Copy config files and templates
COPY --from=builder /app/config /config
COPY --from=builder /app/templates /templates

# Use non-root user
USER appuser

# Expose API port
EXPOSE 8080

# Set secure environment variables
ENV SCAN_TIMEOUT="5m" \
    LOG_LEVEL="info" \
    SCAN_CACHE_DIR="/tmp/trivy-cache" \
    TRIVY_NO_PROGRESS="true" \
    TRIVY_TIMEOUT="5m" \
    TRIVY_SKIP_UPDATE="false" \
    TRIVY_IGNORE_UNFIXED="false" \
    TRIVY_SEVERITY="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD [ "/vuln-scanner", "healthcheck" ]

# Set entrypoint
ENTRYPOINT ["/vuln-scanner"]
CMD ["serve"]
