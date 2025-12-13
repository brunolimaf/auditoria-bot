package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/rand" // <--- Importante para gerar números aleatórios
	"net/http"
	"net/url"
	"strings"
	"time"

	"os"

	"github.com/PuerkitoBio/goquery"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt" // <--- Adicione este
)

var db *sql.DB

type Credenciais struct {
	Usuario string `json:"usuario"`
	Senha   string `json:"senha"`
}

// Matriz de Auditoria (Itens que o robô procura)
//var itensObrigatorios = []string{
//	"licitações", "contratos", "despesas", "receitas",
//	"folha de pagamento", "diárias", "sic", "ouvidoria",
//}

// === ESTRUTURAS DE DADOS (JSON) ===

type ResultadoItem struct {
	ItemProcurado string `json:"item_procurado"`
	Status        string `json:"status"`
	UrlEncontrada string `json:"url_encontrada"`
}

type RelatorioFinal struct {
	Id      int             `json:"id"`
	Codigo  string          `json:"codigo"` // <--- NOVO CAMPO (ex: 2025AB1020)
	UrlAlvo string          `json:"url_alvo"`
	Data    string          `json:"data"`
	Itens   []ResultadoItem `json:"itens"`
}

func main() {
	// 0. Semente
	rand.Seed(time.Now().UnixNano())

	// 1. Conexão com Banco de Dados (Inteligente)
	// Se tiver a variável DATABASE_URL (nuvem), usa ela. Se não, usa a local.
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		connStr = "postgres://auditor:senha_segura@127.0.0.1:5432/auditoria_db?sslmode=disable"
	}

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	// Tenta reconectar algumas vezes (o banco na nuvem pode demorar pra acordar)
	for i := 0; i < 5; i++ {
		if err = db.Ping(); err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}

	// 2. Cria tabelas
	criarTabelas()

	// 3. Configura Servidor
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	// 4. Rotas
	http.HandleFunc("/api/auditar", auditarHandler)
	http.HandleFunc("/api/historico", historicoHandler)
	http.HandleFunc("/api/relatorio", relatorioDetalhesHandler)
	http.HandleFunc("/api/registrar", registrarHandler)
	http.HandleFunc("/api/login", loginHandler)
	//http.HandleFunc("/api/excluir", excluirHandler) // NÃO IMPLEMENTADA!

	// 5. Porta Dinâmica (O Render define a porta na variável PORT)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Println("🔥 Sistema Auditor SIA rodando na porta:", port)
	// Atenção: Mudei para usar a variável 'port'
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// ====================== //
// === AUTENTICAÇÃO ===
// ====================== //

func registrarHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credenciais
	json.NewDecoder(r.Body).Decode(&creds)

	hash, _ := bcrypt.GenerateFromPassword([]byte(creds.Senha), 10)

	// Tenta inserir. Se der erro (ex: usuario duplicado), avisa.
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
	var isAdmin bool // <--- Variável nova

	// Busca o usuário e a flag is_admin
	err := db.QueryRow("SELECT id, username, password_hash, is_admin FROM usuarios WHERE username=$1", creds.Usuario).Scan(&id, &username, &hashSalvo, &isAdmin)
	if err != nil {
		http.Error(w, "Usuário não encontrado", 401)
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(hashSalvo), []byte(creds.Senha)) == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":       id,
			"username": username,
			"is_admin": isAdmin, // <--- Envia pro frontend
		})
	} else {
		http.Error(w, "Senha incorreta", 401)
	}
}

// ==========================================
// ===  LÓGICA DE NEGÓCIO (HANDLERS)      ===
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

	// === CORREÇÃO DE ENTRADA (Input Flexível) ===
	inputUrl := strings.TrimSpace(requestData.Url)

	// Se não tiver http nem https, assume https por padrão
	if !strings.HasPrefix(inputUrl, "http://") && !strings.HasPrefix(inputUrl, "https://") {
		inputUrl = "https://" + inputUrl
	}

	// Atualiza a variável para usar a URL corrigida
	requestData.Url = inputUrl

	fmt.Println("Iniciando auditoria em:", requestData.Url)

	// ... (O resto da função continua igual: chama realizarAuditoria, gera código, salva no banco...)
	// Apenas certifique-se de passar 'requestData.Url' (a corrigida) para as funções abaixo.

	itensResultado, err := realizarAuditoria(requestData.Url)
	if err != nil {
		// Loga o erro no terminal para você ver o detalhe
		fmt.Println("Erro Scraper:", err)
		http.Error(w, "Erro ao acessar o site: "+err.Error(), 500)
		return
	}

	codigoGerado := gerarCodigoRelatorio()
	var relatorioId int

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

	w.Header().Set("Content-Type", "application/json")
	response := RelatorioFinal{
		Id:      relatorioId,
		Codigo:  codigoGerado,
		UrlAlvo: requestData.Url,
		Data:    time.Now().Format("02/01/2006 15:04:05"),
		Itens:   itensResultado,
	}
	json.NewEncoder(w).Encode(response)
}

// ROTA 2: LISTAR HISTÓRICO (GET)
func historicoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userId := r.URL.Query().Get("user_id")

	// 1. Verifica no banco se esse usuário é ADMIN
	var isAdmin bool
	err := db.QueryRow("SELECT is_admin FROM usuarios WHERE id = $1", userId).Scan(&isAdmin)
	if err != nil {
		http.Error(w, "Erro ao verificar permissão", 500)
		return
	}

	var query string
	var rows *sql.Rows

	if isAdmin {
		// CENÁRIO 1: É CHEFE -> Mostra TUDO de TODOS (Sem WHERE user_id)
		fmt.Println("Auditor Chefe acessando histórico completo...")
		query = `
			SELECT r.id, r.codigo, r.url_alvo, to_char(r.data_auditoria, 'DD/MM/YYYY HH24:MI:SS') as data_fmt, u.username
			FROM relatorios r
			JOIN usuarios u ON r.user_id = u.id
			ORDER BY r.data_auditoria DESC
		`
		rows, err = db.Query(query)
	} else {
		// CENÁRIO 2: É COMUM -> Mostra só os dele
		query = `
			SELECT r.id, r.codigo, r.url_alvo, to_char(r.data_auditoria, 'DD/MM/YYYY HH24:MI:SS') as data_fmt, u.username
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

	// ... (o resto da função scan e json continua idêntico) ...
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

// ROTA 3: DETALHES DE UM RELATÓRIO ESPECÍFICO (GET)
func relatorioDetalhesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "ID obrigatório", 400)
		return
	}

	var relatorio RelatorioFinal

	// Busca Cabeçalho (incluindo o código)
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
// === FUNÇÕES AUXILIARES (ROBÔ E BANCO) ===
// ==========================================

// Função que gera: 2025 + Duas Letras + 4 Números (Ex: 2025AB1092)
func gerarCodigoRelatorio() string {
	ano := time.Now().Year()
	letras := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	l1 := string(letras[rand.Intn(len(letras))])
	l2 := string(letras[rand.Intn(len(letras))])

	numeros := rand.Intn(10000) // 0 a 9999

	return fmt.Sprintf("%d%s%s%04d", ano, l1, l2, numeros)
}

// Lógica do Robô Auditor (GoQuery)
func realizarAuditoria(urlAlvo string) ([]ResultadoItem, error) {
	// === PASSO 1: Busca o Checklist no Banco de Dados ===
	rows, err := db.Query("SELECT termo FROM checklist")
	if err != nil {
		return nil, fmt.Errorf("erro ao ler checklist: %v", err)
	}
	defer rows.Close()

	var listaItens []string
	for rows.Next() {
		var t string
		rows.Scan(&t)
		listaItens = append(listaItens, t)
	}
	// ====================================================

	// Configuração do Cliente HTTP (Robô Blindado)
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
		return nil, fmt.Errorf("site retornou status %d", res.StatusCode)
	}

	baseUrl, err := url.Parse(urlAlvo)
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, err
	}

	var resultados []ResultadoItem

	// === PASSO 2: Usa a lista que veio do BANCO (listaItens) ===
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

			// Verifica se contém o termo
			if strings.Contains(textoLink, termo) || strings.Contains(strings.ToLower(href), termo) {
				status = "ENCONTRADO"

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

// Criação e Reset das Tabelas
// Criação e Reset das Tabelas
func criarTabelas() {
	// Apaga tudo para garantir o reset
	db.Exec(`DROP TABLE IF EXISTS itens_relatorio`)
	db.Exec(`DROP TABLE IF EXISTS relatorios`)
	db.Exec(`DROP TABLE IF EXISTS checklist`)
	db.Exec(`DROP TABLE IF EXISTS usuarios`)

	// Recria Usuários
	db.Exec(`CREATE TABLE IF NOT EXISTS usuarios (
		id SERIAL PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		is_admin BOOLEAN DEFAULT FALSE
	);`)

	// === CORREÇÃO AQUI ===
	// Geramos o hash da senha "123" agora mesmo, dinamicamente
	senhaAdmin := "123"
	hashCalculado, _ := bcrypt.GenerateFromPassword([]byte(senhaAdmin), 10)

	// Inserimos o Auditor Chefe com a senha que acabamos de gerar
	_, err := db.Exec(`INSERT INTO usuarios (id, username, password_hash, is_admin) 
             VALUES (1, 'Auditor Chefe', $1, TRUE) 
             ON CONFLICT (id) DO NOTHING`, string(hashCalculado))

	if err != nil {
		fmt.Println("Erro ao criar Admin:", err)
	}

	// Recria Relatórios
	db.Exec(`CREATE TABLE IF NOT EXISTS relatorios (
		id SERIAL PRIMARY KEY,
		codigo TEXT UNIQUE NOT NULL,
		user_id INT REFERENCES usuarios(id),
		url_alvo TEXT NOT NULL,
		data_auditoria TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`)

	// Recria Itens
	db.Exec(`CREATE TABLE IF NOT EXISTS itens_relatorio (
		id SERIAL PRIMARY KEY,
		relatorio_id INT REFERENCES relatorios(id) ON DELETE CASCADE,
		item_procurado TEXT NOT NULL,
		url_encontrada TEXT,
		status TEXT NOT NULL
	);`)

	// 4. === NOVA TABELA DE CHECKLIST ===
	db.Exec(`CREATE TABLE IF NOT EXISTS checklist (
		id SERIAL PRIMARY KEY,
		termo TEXT UNIQUE NOT NULL
	);`)

	// Insere os itens padrão no banco
	itensPadrao := []string{
		"licitações", "contratos", "despesas", "receitas",
		"folha de pagamento", "diárias", "sic", "ouvidoria",
		"rreo", "rgf", "obras", // Adicionei uns novos de exemplo
	}

	for _, item := range itensPadrao {
		db.Exec(`INSERT INTO checklist (termo) VALUES ($1) ON CONFLICT DO NOTHING`, item)
	}

	fmt.Println(">>> Banco atualizado! Checklist carregado no banco.")
}
