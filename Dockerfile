# Estágio 1: Construção (Builder)
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copia os arquivos de dependência
COPY go.mod go.sum ./
RUN go mod download

# Copia todo o código fonte (pastas cmd, internal, etc)
COPY . .

# === MUDANÇA CRÍTICA AQUI ===
# Antes era: go build -o main .
# Agora apontamos para a pasta onde está o main:
RUN go build -o main ./cmd/app
# ============================

# ... (no estágio final FROM alpine:latest)

# Instala o tzdata (base de dados de fusos)
RUN apk add --no-cache tzdata ca-certificates

# Define a variável de ambiente
ENV TZ=America/Sao_Paulo


# Estágio 2: Execução (Runner)
FROM alpine:latest

WORKDIR /root/

# Instala fuso horário e certificados de segurança (Importante para o Robô)
RUN apk add --no-cache tzdata ca-certificates

# Copia o binário construído
COPY --from=builder /app/main .
# Copia a pasta estática (HTML/CSS)
COPY --from=builder /app/static ./static

# Configurações de Ambiente
ENV TZ=America/Sao_Paulo

# Comando para rodar
CMD ["./main"]