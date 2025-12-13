# Estágio 1: Construção (Build)
# MUDANÇA AQUI: Atualizamos para 1.25 para bater com o seu go.mod
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copia os arquivos de dependência
COPY go.mod go.sum ./
RUN go mod download

# Copia o código fonte
COPY . .

# Compila o executável chamado "main"
RUN go build -o main .

# Estágio 2: Execução (Imagem leve)
FROM alpine:latest

WORKDIR /root/

# Copia o executável do estágio anterior
COPY --from=builder /app/main .

# Copia a pasta static (HTML/JS) para a imagem final
COPY --from=builder /app/static ./static

# Comando para rodar
CMD ["./main"]