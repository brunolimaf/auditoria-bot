package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

// === ESTRUTURAS DE DADOS ===

type Credenciais struct {
	Usuario string `json:"usuario"`
	Senha   string `json:"senha"`
}

type ResultadoItem struct {
	ItemProcurado string `json:"item_procurado"`
	Status        string `json:"status"`
	UrlEncontrada string `json:"url_encontrada"`
}

type RelatorioFinal struct {
	Id      int             `json:"id"`
	Codigo  string          `json:"codigo"`
	UrlAlvo string          `json:"url_alvo"`
	Data    string          `json:"data"`
	Itens   []ResultadoItem `json:"itens"`
}

// ==========================================
// ===             MAIN                   ===
// ==========================================

func main() {
	// 0. Semente Aleatória
	rand.Seed(time.Now().UnixNano())

	// 1. Configura Fuso Horário (Brasília)
	loc, err := time.LoadLocation("America/Sao_Paulo")
	if err != nil {
		loc = time.Local
		fmt.Println("Aviso: Fuso horário SP não carregado, usando local do sistema.")
	}
	time.Local = loc // Define globalmente para o Go

	// 2. Conexão com Banco de Dados (Nuvem ou Local)
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		connStr = "postgres://auditor:senha_segura@127.0.0.1:5432/auditoria_db?sslmode=disable"
	}

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	// Tenta conectar (Retry logic para nuvem)
	for i := 0; i < 5; i++ {
		if err = db.Ping(); err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}

	// Força o Banco a trabalhar no horário de Brasília
	db.Exec("SET TIME ZONE 'America/Sao_Paulo'")

	// 3. Inicializa Tabelas e Dados Padrão
	criarTabelas()

	// 4. Configura Servidor de Arquivos (Frontend)
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	// 5. Rotas da API
	http.HandleFunc("/api/auditar", auditarHandler)
	http.HandleFunc("/api/historico", historicoHandler)
	http.HandleFunc("/api/relatorio", relatorioDetalhesHandler)
	http.HandleFunc("/api/registrar", registrarHandler)
	http.HandleFunc("/api/login", loginHandler)
	// Rota de excluir removida conforme solicitado

	// 6. Define Porta (Render usa a env PORT)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Println("🔥 Sistema Auditor SIA rodando na porta:", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// ==========================================
// ===           AUTENTICAÇÃO             ===
// ==========================================

func registrarHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credenciais
	json.NewDecoder(r.Body).Decode(&creds)

	hash, _ := bcrypt.GenerateFromPassword([]byte(creds.Senha), 10)

	_, err := db.Exec("INSERT INTO usuarios (username, password_hash) VALUES ($1, $2)", creds.Usuario, string(hash))
	if err != nil {
		http.Error(w, "Erro: Usuário já existe ou dados inválidos", 400)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"msg": "Criado com sucesso"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credenciais
	json.NewDecoder(r.Body).Decode(&creds)

	var id int
	var hashSalvo, username string
	var isAdmin bool

	err := db.QueryRow("SELECT id, username, password_hash, is_admin FROM usuarios WHERE username=$1", creds.Usuario).Scan(&id, &username, &hashSalvo, &isAdmin)
	if err != nil {
		http.Error(w, "Usuário não encontrado", 401)
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(hashSalvo), []byte(creds.Senha)) == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":       id,
			"username": username,
			"is_admin": isAdmin,
		})
	} else {
		http.Error(w, "Senha incorreta", 401)
	}
}

// ==========================================
// ===       LÓGICA DE AUDITORIA          ===
// ==========================================

// ROTA 1: CRIAR NOVA AUDITORIA (POST)
func auditarHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método inválido", 405)
		return
	}

	var requestData struct {
		Url    string `json:"url"`
		UserId int    `json:"user_id"`
	}
	json.NewDecoder(r.Body).Decode(&requestData)

	// Limpeza e correção da URL
	inputUrl := strings.TrimSpace(requestData.Url)
	if !strings.HasPrefix(inputUrl, "http://") && !strings.HasPrefix(inputUrl, "https://") {
		inputUrl = "https://" + inputUrl
	}
	requestData.Url = inputUrl

	fmt.Println("Iniciando auditoria em:", requestData.Url)

	// Executa o Robô
	itensResultado, err := realizarAuditoria(requestData.Url)
	if err != nil {
		fmt.Println("Erro Scraper:", err)
		http.Error(w, "Erro ao acessar o site: "+err.Error(), 500)
		return
	}

	codigoGerado := gerarCodigoRelatorio()
	var relatorioId int

	// Salva no Banco
	err = db.QueryRow(`INSERT INTO relatorios (user_id, url_alvo, codigo) VALUES ($1, $2, $3) RETURNING id`,
		requestData.UserId, requestData.Url, codigoGerado).Scan(&relatorioId)

	if err == nil {
		for _, item := range itensResultado {
			db.Exec(`INSERT INTO itens_relatorio (relatorio_id, item_procurado, url_encontrada, status) VALUES ($1, $2, $3, $4)`,
				relatorioId, item.ItemProcurado, item.UrlEncontrada, item.Status)
		}
	} else {
		fmt.Println("Erro ao salvar:", err)
		http.Error(w, "Erro banco", 500)
		return
	}

	// Resposta JSON
	w.Header().Set("Content-Type", "application/json")
	response := RelatorioFinal{
		Id:      relatorioId,
		Codigo:  codigoGerado,
		UrlAlvo: requestData.Url,
		Data:    time.Now().In(time.Local).Format("02/01/2006 15:04:05"), // Hora local
		Itens:   itensResultado,
	}
	json.NewEncoder(w).Encode(response)
}

// ROTA 2: LISTAR HISTÓRICO (GET)
func historicoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userId := r.URL.Query().Get("user_id")

	// Verifica se é ADMIN
	var isAdmin bool
	db.QueryRow("SELECT is_admin FROM usuarios WHERE id = $1", userId).Scan(&isAdmin)

	var query string
	var rows *sql.Rows
	var err error

	if isAdmin {
		// Admin vê tudo
		query = `
			SELECT r.id, r.codigo, r.url_alvo, to_char(r.data_auditoria, 'DD/MM/YYYY HH24:MI:SS'), u.username
			FROM relatorios r
			JOIN usuarios u ON r.user_id = u.id
			ORDER BY r.data_auditoria DESC
		`
		rows, err = db.Query(query)
	} else {
		// Usuário comum vê só os seus
		query = `
			SELECT r.id, r.codigo, r.url_alvo, to_char(r.data_auditoria, 'DD/MM/YYYY HH24:MI:SS'), u.username
			FROM relatorios r
			JOIN usuarios u ON r.user_id = u.id
			WHERE r.user_id = $1
			ORDER BY r.data_auditoria DESC
		`
		rows, err = db.Query(query, userId)
	}

	if err != nil {
		http.Error(w, "Erro ao buscar histórico", 500)
		return
	}
	defer rows.Close()

	var lista []map[string]interface{}
	for rows.Next() {
		var id int
		var codigo, url, data, usuario string
		if err := rows.Scan(&id, &codigo, &url, &data, &usuario); err != nil {
			continue
		}
		lista = append(lista, map[string]interface{}{
			"id": id, "codigo": codigo, "url": url, "data": data, "usuario": usuario,
		})
	}

	if lista == nil {
		lista = []map[string]interface{}{}
	}
	json.NewEncoder(w).Encode(lista)
}

// ROTA 3: DETALHES DE UM RELATÓRIO (GET)
func relatorioDetalhesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "ID obrigatório", 400)
		return
	}

	var relatorio RelatorioFinal

	// Busca Cabeçalho
	queryHeader := `
		SELECT r.id, r.codigo, r.url_alvo, to_char(r.data_auditoria, 'DD/MM/YYYY HH24:MI:SS')
		FROM relatorios r
		WHERE r.id = $1
	`
	err := db.QueryRow(queryHeader, idStr).Scan(&relatorio.Id, &relatorio.Codigo, &relatorio.UrlAlvo, &relatorio.Data)
	if err != nil {
		http.Error(w, "Relatório não encontrado", 404)
		return
	}

	// Busca Itens
	queryItens := `
		SELECT item_procurado, status, coalesce(url_encontrada, '')
		FROM itens_relatorio
		WHERE relatorio_id = $1
	`
	rows, err := db.Query(queryItens, idStr)
	if err != nil {
		http.Error(w, "Erro ao buscar itens", 500)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var item ResultadoItem
		rows.Scan(&item.ItemProcurado, &item.Status, &item.UrlEncontrada)
		relatorio.Itens = append(relatorio.Itens, item)
	}

	json.NewEncoder(w).Encode(relatorio)
}

// ==========================================
// ===     FUNÇÕES AUXILIARES             ===
// ==========================================

// Gera código: 2025AB1092
func gerarCodigoRelatorio() string {
	ano := time.Now().Year()
	letras := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	l1 := string(letras[rand.Intn(len(letras))])
	l2 := string(letras[rand.Intn(len(letras))])
	numeros := rand.Intn(10000)
	return fmt.Sprintf("%d%s%s%04d", ano, l1, l2, numeros)
}

// Robô Scraper (Blindado + Checklist Dinâmico)
func realizarAuditoria(urlAlvo string) ([]ResultadoItem, error) {
	// 1. Busca Checklist do Banco
	rows, err := db.Query("SELECT termo FROM checklist")
	if err != nil {
		return nil, fmt.Errorf("erro checklist: %v", err)
	}
	defer rows.Close()

	var listaItens []string
	for rows.Next() {
		var t string
		rows.Scan(&t)
		listaItens = append(listaItens, t)
	}

	// 2. Configura Cliente HTTP (Ignora SSL e define User-Agent)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", urlAlvo, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("status code %d", res.StatusCode)
	}

	// 3. Parser HTML
	baseUrl, err := url.Parse(urlAlvo)
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, err
	}

	var resultados []ResultadoItem

	// 4. Varredura
	for _, termo := range listaItens {
		status := "AUSENTE"
		linkEncontrado := ""

		doc.Find("a").EachWithBreak(func(i int, s *goquery.Selection) bool {
			textoLink := strings.ToLower(s.Text())
			href, exists := s.Attr("href")
			if !exists {
				return true
			}

			textoLink = strings.TrimSpace(textoLink)
			href = strings.TrimSpace(href)

			if strings.Contains(textoLink, termo) || strings.Contains(strings.ToLower(href), termo) {
				status = "ENCONTRADO"

				// Resolve URL Relativa (ex: /contratos -> https://site.com/contratos)
				hrefUrl, err := url.Parse(href)
				if err == nil {
					linkEncontrado = baseUrl.ResolveReference(hrefUrl).String()
				} else {
					linkEncontrado = href
				}
				return false
			}
			return true
		})

		resultados = append(resultados, ResultadoItem{
			ItemProcurado: termo,
			Status:        status,
			UrlEncontrada: linkEncontrado,
		})
	}

	return resultados, nil
}

// Criação e Reset das Tabelas (Com Admin Dinâmico)
func criarTabelas() {
	// Apaga tabelas antigas para garantir estrutura
	db.Exec(`DROP TABLE IF EXISTS itens_relatorio`)
	db.Exec(`DROP TABLE IF EXISTS relatorios`)
	db.Exec(`DROP TABLE IF EXISTS checklist`)
	db.Exec(`DROP TABLE IF EXISTS usuarios`)

	// 1. Usuários
	db.Exec(`CREATE TABLE IF NOT EXISTS usuarios (
		id SERIAL PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		is_admin BOOLEAN DEFAULT FALSE
	);`)

	// Cria o Admin "Auditor Chefe" com senha "123"
	senhaAdmin := "123"
	hashCalculado, _ := bcrypt.GenerateFromPassword([]byte(senhaAdmin), 10)

	_, err := db.Exec(`INSERT INTO usuarios (id, username, password_hash, is_admin) 
             VALUES (1, 'Auditor Chefe', $1, TRUE) 
             ON CONFLICT (id) DO NOTHING`, string(hashCalculado))
	if err != nil {
		fmt.Println("Erro criar admin:", err)
	}

	// 2. Relatórios
	db.Exec(`CREATE TABLE IF NOT EXISTS relatorios (
		id SERIAL PRIMARY KEY,
		codigo TEXT UNIQUE NOT NULL,
		user_id INT REFERENCES usuarios(id),
		url_alvo TEXT NOT NULL,
		data_auditoria TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`)

	// 3. Itens do Relatório
	db.Exec(`CREATE TABLE IF NOT EXISTS itens_relatorio (
		id SERIAL PRIMARY KEY,
		relatorio_id INT REFERENCES relatorios(id) ON DELETE CASCADE,
		item_procurado TEXT NOT NULL,
		url_encontrada TEXT,
		status TEXT NOT NULL
	);`)

	// 4. Checklist Dinâmico
	db.Exec(`CREATE TABLE IF NOT EXISTS checklist (
		id SERIAL PRIMARY KEY,
		termo TEXT UNIQUE NOT NULL
	);`)

	// Popula Checklist Padrão
	itensPadrao := []string{
		"licitações", "contratos", "despesas", "receitas",
		"folha de pagamento", "diárias", "sic", "ouvidoria",
		"rreo", "rgf", "obras",
	}
	for _, item := range itensPadrao {
		db.Exec(`INSERT INTO checklist (termo) VALUES ($1) ON CONFLICT DO NOTHING`, item)
	}

	fmt.Println(">>> Banco atualizado com sucesso!")
}
