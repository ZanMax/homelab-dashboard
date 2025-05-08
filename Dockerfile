FROM golang:1.22-alpine AS builder
WORKDIR /app
RUN apk add --no-cache nmap iputils git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags="-w -s" -o /app/dashboard_server .

FROM alpine:latest
WORKDIR /app
RUN apk add --no-cache nmap iputils ca-certificates
COPY --from=builder /app/dashboard_server /app/dashboard_server
COPY templates ./templates
COPY config.yaml ./config.yaml
EXPOSE 8080
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser
ENTRYPOINT ["/app/dashboard_server"]