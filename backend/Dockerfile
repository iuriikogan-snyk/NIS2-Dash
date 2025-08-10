# Use the official Golang image to create a build artifact.
# This is known as a multi-stage build.
FROM golang:1.23-alpine AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod
COPY go.mod ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source code
COPY . .

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux go build -o nis2-dash ./cmd/main.go

# Start a new stage from scratch for a smaller image
FROM alpine:latest

WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/nis2-dash .

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["./nis2-dash"]
