package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"

	// NOSSOS IMPORTS INTERNOS
	// Certifique-se que o nome do módulo aqui (auditor-bot) é o mesmo do go.mod
	"auditor-bot/internal/handlers"
	"auditor-bot/internal/repositories"
	"auditor-bot/internal/services"
)

func main() {
	// 0. Configurações Iniciais
	// 0. Configurações de Fuso Horário (FIX: RECOLOCADO AQUI)
	// Isso garante que time.Now() pegue o horário certo no código Go
	loc, err := time.LoadLocation("America/Sao_Paulo")
	if err != nil {
		// Fallback se não tiver o tzdata instalado
		loc = time.Local
		fmt.Println("Aviso: Fuso horário SP não carregado, usando local do sistema.")
	}
	time.Local = loc // Define globalmente
	// ========================================================

	// 1. Conexão com Banco
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		connStr = "postgres://auditor:senha_segura@127.0.0.1:5432/auditoria_db?sslmode=disable"
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	// Retry logic simples
	if err = db.Ping(); err != nil {
		fmt.Println("Aviso: Banco de dados demorando a responder...", err)
	}

	// 2. INJEÇÃO DE DEPENDÊNCIA (Ligando os componentes)

	// CAMADA 1: Repositório (Fala com o Banco)
	auditRepo := repositories.NewAuditoriaRepository(db)

	// === ADICIONE ESTAS LINHAS AQUI ===
	// Inicializa tabelas e cria o admin se não existirem
	if err := auditRepo.InicializarTabelas(); err != nil {
		log.Fatal("Falha ao inicializar banco de dados:", err)
	}
	// ==================================

	// CAMADA 2: Serviço (Tem a lógica do Robô)
	roboService := services.NewRoboService(auditRepo)

	// CAMADA 3: Handlers (Recebem as rotas HTTP)
	// Precisamos criar instâncias para CADA tipo de handler
	auditoriaHandler := handlers.NewAuditoriaHandler(roboService)
	authHandler := handlers.NewAuthHandler(roboService)           // <--- FALTAVA ISSO
	relatorioHandler := handlers.NewRelatorioHandler(roboService) // <--- FALTAVA ISSO

	// 3. Configura Servidor de Arquivos (Frontend)
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	// 4. REGISTRO DAS ROTAS (Ligando os fios)

	// Rotas de Auditoria
	http.HandleFunc("/api/auditar", auditoriaHandler.Auditar)

	// Rotas de Autenticação (Login e Registro)
	http.HandleFunc("/api/registrar", authHandler.Registrar) // <--- AGORA VAI FUNCIONAR
	http.HandleFunc("/api/login", authHandler.Login)         // <--- AGORA VAI FUNCIONAR

	// Rotas de Histórico e Relatórios
	http.HandleFunc("/api/historico", relatorioHandler.ListarHistorico)
	http.HandleFunc("/api/relatorio", relatorioHandler.Detalhes)

	// 5. Inicia o Servidor
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Println("🔥 SIA Modular rodando na porta:", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
