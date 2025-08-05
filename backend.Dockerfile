# Stage 1: Build
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY backend/go.mod ./
COPY backend/cmd ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/main .
# Stage 2: Final
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/main .
EXPOSE 8080
CMD ["/app/main"]