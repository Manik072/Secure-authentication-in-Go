# minimal Dockerfile for secure-auth
FROM golang:1.21-alpine AS build
WORKDIR /app
COPY . .
RUN go build -o secure-auth ./cmd

FROM alpine:3.18
WORKDIR /app
COPY --from=build /app/secure-auth ./secure-auth
CMD ["/app/secure-auth"]
