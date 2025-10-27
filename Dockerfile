FROM golang:1.25-alpine

# Install GPG, GCC, X11 libraries, and other necessary tools for CGO
RUN apk add --no-cache gnupg bash gcc musl-dev libx11-dev libxcursor-dev libxfixes-dev

# Create a working directory
WORKDIR /app

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 go build -o secretshare .

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Keep the container running
CMD ["tail", "-f", "/dev/null"]