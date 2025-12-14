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
	"sync"
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
	rand.Seed(time.Now().UnixNano())

	loc, err := time.LoadLocation("America/Sao_Paulo")
	if err != nil {
		loc = time.Local
		fmt.Println("Aviso: Fuso horário SP não carregado.")
	}
	time.Local = loc

	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		connStr = "postgres://auditor:senha_segura@127.0.0.1:5432/auditoria_db?sslmode=disable"
	}

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		if err = db.Ping(); err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}

	db.Exec("SET TIME ZONE 'America/Sao_Paulo'")
	criarTabelas()

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	http.HandleFunc("/api/auditar", auditarHandler)
	http.HandleFunc("/api/historico", historicoHandler)
	http.HandleFunc("/api/relatorio", relatorioDetalhesHandler)
	http.HandleFunc("/api/registrar", registrarHandler)
	http.HandleFunc("/api/login", loginHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Println("🔥 Sistema Auditor SIA (V. Final) rodando na porta:", port)
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
		http.Error(w, "Erro: Usuário já existe", 400)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"msg": "Criado"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credenciais
	json.NewDecoder(r.Body).Decode(&creds)
	var id int
	var hash, user string
	var admin bool
	err := db.QueryRow("SELECT id, username, password_hash, is_admin FROM usuarios WHERE username=$1", creds.Usuario).Scan(&id, &user, &hash, &admin)
	if err != nil {
		http.Error(w, "Usuário inválido", 401)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(creds.Senha)) == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"id": id, "username": user, "is_admin": admin})
	} else {
		http.Error(w, "Senha incorreta", 401)
	}
}

// ==========================================
// ===       LÓGICA DE AUDITORIA          ===
// ==========================================

func auditarHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método inválido", 405)
		return
	}

	var reqData struct {
		Url    string `json:"url"`
		UserId int    `json:"user_id"`
	}
	json.NewDecoder(r.Body).Decode(&reqData)

	reqData.Url = strings.TrimSpace(reqData.Url)
	if !strings.HasPrefix(reqData.Url, "http") {
		reqData.Url = "https://" + reqData.Url
	}

	fmt.Println("🔎 Iniciando Auditoria Profunda em:", reqData.Url)

	itensResultado, err := realizarAuditoriaProfunda(reqData.Url)
	if err != nil {
		fmt.Println("Erro Scraper:", err)
		http.Error(w, "Erro ao acessar site: "+err.Error(), 500)
		return
	}

	codigo := gerarCodigoRelatorio()
	var rId int
	err = db.QueryRow(`INSERT INTO relatorios (user_id, url_alvo, codigo) VALUES ($1, $2, $3) RETURNING id`,
		reqData.UserId, reqData.Url, codigo).Scan(&rId)

	if err == nil {
		for _, item := range itensResultado {
			db.Exec(`INSERT INTO itens_relatorio (relatorio_id, item_procurado, url_encontrada, status) VALUES ($1, $2, $3, $4)`,
				rId, item.ItemProcurado, item.UrlEncontrada, item.Status)
		}
	} else {
		http.Error(w, "Erro banco", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RelatorioFinal{
		Id:      rId,
		Codigo:  codigo,
		UrlAlvo: reqData.Url,
		Data:    time.Now().In(time.Local).Format("02/01/2006 15:04:05"),
		Itens:   itensResultado,
	})
}

// ==========================================
// ===     INTELIGÊNCIA DO ROBÔ           ===
// ==========================================

func realizarAuditoriaProfunda(urlPrincipal string) ([]ResultadoItem, error) {
	rows, err := db.Query("SELECT termo FROM checklist")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var termos []string
	for rows.Next() {
		var t string
		rows.Scan(&t)
		termos = append(termos, t)
	}

	mapaResultados := make(map[string]ResultadoItem)
	for _, t := range termos {
		mapaResultados[t] = ResultadoItem{ItemProcurado: t, Status: "AUSENTE", UrlEncontrada: ""}
	}

	// Discovery (Adiciona Ouvidoria na busca ativa)
	urlsParaEscanear := descobrirPortais(urlPrincipal)
	fmt.Println(">> Alvos iniciais:", urlsParaEscanear)

	fila := urlsParaEscanear
	visitadas := make(map[string]bool)
	var mu sync.Mutex

	limitePaginas := 20 // Aumentei um pouco para garantir profundidade
	contador := 0

	for len(fila) > 0 && contador < limitePaginas {
		urlAlvo := fila[0]
		fila = fila[1:]

		if visitadas[urlAlvo] {
			continue
		}
		visitadas[urlAlvo] = true
		contador++

		fmt.Println("   ... Lendo:", urlAlvo)

		doc, err := baixarHTML(urlAlvo)
		if err != nil {
			continue
		}

		novasUrls := analisarDocumento(doc, urlAlvo, termos, mapaResultados, &mu)

		for _, nova := range novasUrls {
			if !visitadas[nova] {
				fila = append(fila, nova)
			}
		}
	}

	var listaFinal []ResultadoItem
	for _, t := range termos {
		listaFinal = append(listaFinal, mapaResultados[t])
	}
	return listaFinal, nil
}

func analisarDocumento(doc *goquery.Document, urlAtual string, termos []string, mapa map[string]ResultadoItem, mu *sync.Mutex) []string {
	baseUrl, _ := url.Parse(urlAtual)
	var linksInteressantes []string

	// Função interna para processar qualquer URL encontrada (seja link ou iframe)
	processarLink := func(linkRaw string, textoContexto string) {
		linkFinal := linkRaw
		hrefUrl, err := url.Parse(linkRaw)
		if err == nil && baseUrl != nil {
			linkFinal = baseUrl.ResolveReference(hrefUrl).String()
		}

		// Verifica Checklist
		for _, termo := range termos {
			mu.Lock()
			jaAchou := mapa[termo].Status == "ENCONTRADO"
			mu.Unlock()

			if jaAchou {
				continue
			}

			// CORREÇÃO CRUCIAL:
			// Verifica se o termo está no texto (contexto) OU na URL (ex: receita.php)
			if strings.Contains(textoContexto, termo) || strings.Contains(strings.ToLower(linkFinal), termo) {
				mu.Lock()
				mapa[termo] = ResultadoItem{
					ItemProcurado: termo,
					Status:        "ENCONTRADO",
					UrlEncontrada: linkFinal,
				}
				mu.Unlock()
			}
		}

		// Drill Down: Busca novos portais
		gatilhos := []string{"transparência", "transparencia", "portal", "acesso a informação", "ouvidoria"}
		ehArquivo := strings.HasSuffix(linkFinal, ".pdf") || strings.HasSuffix(linkFinal, ".zip") || strings.HasSuffix(linkFinal, ".rar")

		if !ehArquivo {
			for _, gatilho := range gatilhos {
				if strings.Contains(textoContexto, gatilho) {
					linksInteressantes = append(linksInteressantes, linkFinal)
					break
				}
			}
		}
	}

	// 1. Processa Links <a>
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}
		texto := extrairTextoRico(s)
		processarLink(href, texto)
	})

	// 2. Processa IFrames (MUITO IMPORTANTE para Fator Sistemas e Ágape)
	doc.Find("iframe").Each(func(i int, s *goquery.Selection) {
		src, exists := s.Attr("src")
		if !exists {
			return
		}
		// Trata o Iframe como um link que tem o texto "transparencia" embutido, para forçar a visita
		processarLink(src, "iframe transparencia sistema externo")

		// Adiciona diretamente à fila de investigação
		linksInteressantes = append(linksInteressantes, src)
	})

	return linksInteressantes
}

func extrairTextoRico(s *goquery.Selection) string {
	texto := s.Text()
	title, _ := s.Attr("title")
	img := s.Find("img")
	alt := img.AttrOr("alt", "")
	imgTitle := img.AttrOr("title", "")
	conteudo := fmt.Sprintf("%s %s %s %s", texto, title, alt, imgTitle)
	return strings.ToLower(strings.TrimSpace(conteudo))
}

func baixarHTML(urlAlvo string) (*goquery.Document, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	req, _ := http.NewRequest("GET", urlAlvo, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", res.StatusCode)
	}
	return goquery.NewDocumentFromReader(res.Body)
}

func descobrirPortais(urlEntrada string) []string {
	u, err := url.Parse(urlEntrada)
	if err != nil {
		return []string{urlEntrada}
	}
	host := u.Hostname()
	scheme := u.Scheme
	hostRaiz := strings.TrimPrefix(host, "www.")

	// Adicionamos OUVIDORIA aqui para forçar a descoberta
	candidatos := []string{
		urlEntrada,
		fmt.Sprintf("%s://transparencia.%s", scheme, hostRaiz),
		fmt.Sprintf("%s://portaldatransparencia.%s", scheme, hostRaiz),
		fmt.Sprintf("%s://portal.%s", scheme, hostRaiz),
		strings.TrimSuffix(urlEntrada, "/") + "/transparencia",
		strings.TrimSuffix(urlEntrada, "/") + "/portal",
		strings.TrimSuffix(urlEntrada, "/") + "/ouvidoria", // <--- NOVO
	}

	var urlsValidas []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, c := range candidatos {
		wg.Add(1)
		go func(teste string) {
			defer wg.Done()
			tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			resp, err := client.Get(teste)
			if err == nil && resp.StatusCode == 200 {
				mu.Lock()
				urlsValidas = append(urlsValidas, teste)
				mu.Unlock()
			}
			if resp != nil {
				resp.Body.Close()
			}
		}(c)
	}
	wg.Wait()
	if len(urlsValidas) == 0 {
		return []string{urlEntrada}
	}
	return urlsValidas
}

// ... (gerarCodigoRelatorio, historicoHandler, relatorioDetalhesHandler)
// Mantenha as funções abaixo iguais.

func gerarCodigoRelatorio() string {
	ano := time.Now().Year()
	letras := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	l1 := string(letras[rand.Intn(len(letras))])
	l2 := string(letras[rand.Intn(len(letras))])
	numeros := rand.Intn(10000)
	return fmt.Sprintf("%d%s%s%04d", ano, l1, l2, numeros)
}

func historicoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userId := r.URL.Query().Get("user_id")
	var isAdmin bool
	db.QueryRow("SELECT is_admin FROM usuarios WHERE id = $1", userId).Scan(&isAdmin)
	var query string
	var rows *sql.Rows
	var err error
	if isAdmin {
		query = `SELECT r.id, r.codigo, r.url_alvo, to_char(r.data_auditoria, 'DD/MM/YYYY HH24:MI:SS'), u.username FROM relatorios r JOIN usuarios u ON r.user_id = u.id ORDER BY r.data_auditoria DESC`
		rows, err = db.Query(query)
	} else {
		query = `SELECT r.id, r.codigo, r.url_alvo, to_char(r.data_auditoria, 'DD/MM/YYYY HH24:MI:SS'), u.username FROM relatorios r JOIN usuarios u ON r.user_id = u.id WHERE r.user_id = $1 ORDER BY r.data_auditoria DESC`
		rows, err = db.Query(query, userId)
	}
	if err != nil {
		http.Error(w, "Erro histórico", 500)
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
		lista = append(lista, map[string]interface{}{"id": id, "codigo": codigo, "url": url, "data": data, "usuario": usuario})
	}
	if lista == nil {
		lista = []map[string]interface{}{}
	}
	json.NewEncoder(w).Encode(lista)
}

func relatorioDetalhesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	idStr := r.URL.Query().Get("id")
	var relatorio RelatorioFinal
	queryHeader := `SELECT r.id, r.codigo, r.url_alvo, to_char(r.data_auditoria, 'DD/MM/YYYY HH24:MI:SS') FROM relatorios r WHERE r.id = $1`
	err := db.QueryRow(queryHeader, idStr).Scan(&relatorio.Id, &relatorio.Codigo, &relatorio.UrlAlvo, &relatorio.Data)
	if err != nil {
		http.Error(w, "Não encontrado", 404)
		return
	}
	queryItens := `SELECT item_procurado, status, coalesce(url_encontrada, '') FROM itens_relatorio WHERE relatorio_id = $1`
	rows, err := db.Query(queryItens, idStr)
	if err != nil {
		http.Error(w, "Erro itens", 500)
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

func criarTabelas() {
	db.Exec(`DROP TABLE IF EXISTS itens_relatorio`)
	db.Exec(`DROP TABLE IF EXISTS relatorios`)
	db.Exec(`DROP TABLE IF EXISTS checklist`)
	db.Exec(`DROP TABLE IF EXISTS usuarios`)

	db.Exec(`CREATE TABLE IF NOT EXISTS usuarios (id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, is_admin BOOLEAN DEFAULT FALSE);`)
	senhaAdmin := "123"
	hashCalculado, _ := bcrypt.GenerateFromPassword([]byte(senhaAdmin), 10)
	db.Exec(`INSERT INTO usuarios (id, username, password_hash, is_admin) VALUES (1, 'Auditor Chefe', $1, TRUE) ON CONFLICT (id) DO NOTHING`, string(hashCalculado))

	db.Exec(`CREATE TABLE IF NOT EXISTS relatorios (id SERIAL PRIMARY KEY, codigo TEXT UNIQUE NOT NULL, user_id INT REFERENCES usuarios(id), url_alvo TEXT NOT NULL, data_auditoria TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`)
	db.Exec(`CREATE TABLE IF NOT EXISTS itens_relatorio (id SERIAL PRIMARY KEY, relatorio_id INT REFERENCES relatorios(id) ON DELETE CASCADE, item_procurado TEXT NOT NULL, url_encontrada TEXT, status TEXT NOT NULL);`)
	db.Exec(`CREATE TABLE IF NOT EXISTS checklist (id SERIAL PRIMARY KEY, termo TEXT UNIQUE NOT NULL);`)

	// === CORREÇÃO CRÍTICA NO CHECKLIST ===
	// Usamos o singular e radicais das palavras para pegar variações (receita.php, receitas, despesas, despesa...)
	itensPadrao := []string{
		"licitacao, dispensa", // pega licitação, licitações, licitacoes
		"contrato",            // pega contrato, contratos
		"despesa",             // pega despesa, despesas, despesa.php
		"receita",             // pega receita, receitas, receita.php
		"folha",               // pega folha de pagamento
		"diaria",              // pega diaria, diarias
		"sic",                 // esic, sic
		"ouvidoria",           // ouvidoria
		"rreo",
		"rgf",
		"obra",
		"convenio",
		"lei municipal",
		"estrutura organizacional",
	}
	for _, item := range itensPadrao {
		db.Exec(`INSERT INTO checklist (termo) VALUES ($1) ON CONFLICT DO NOTHING`, item)
	}
	fmt.Println(">>> Banco atualizado com sucesso!")
}
