# Estágio 1: Construção
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o main .

# Estágio 2: Execução
FROM alpine:latest

WORKDIR /root/

# === MUDANÇA AQUI: Instalamos o tzdata ===
RUN apk add --no-cache tzdata
# =========================================

COPY --from=builder /app/main .
COPY --from=builder /app/static ./static

# Define a variável de ambiente para o Linux já acordar no Brasil
ENV TZ=America/Sao_Paulo

CMD ["./main"]