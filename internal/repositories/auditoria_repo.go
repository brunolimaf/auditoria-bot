package repositories

import (
	"auditor-bot/internal/models"
	"database/sql"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// AuditoriaRepository conecta o código ao banco de dados
type AuditoriaRepository struct {
	DB *sql.DB
}

func NewAuditoriaRepository(db *sql.DB) *AuditoriaRepository {
	return &AuditoriaRepository{DB: db}
}

// ==========================================
// ===       FUNÇÕES DE CHECKLIST         ===
// ==========================================

func (r *AuditoriaRepository) GetChecklist() ([]string, error) {
	rows, err := r.DB.Query("SELECT termo FROM checklist")
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
	return termos, nil
}

// ==========================================
// ===       FUNÇÕES DE RELATÓRIO         ===
// ==========================================

func (r *AuditoriaRepository) SalvarRelatorio(userId int, url, codigo string, itens []models.ResultadoItem) (int, error) {
	var relatorioId int

	// Inicia transação (se der erro no meio, cancela tudo)
	tx, err := r.DB.Begin()
	if err != nil {
		return 0, err
	}

	// 1. Salva o cabeçalho
	err = tx.QueryRow(`INSERT INTO relatorios (user_id, url_alvo, codigo) VALUES ($1, $2, $3) RETURNING id`,
		userId, url, codigo).Scan(&relatorioId)

	if err != nil {
		tx.Rollback()
		return 0, err
	}

	// 2. Salva os itens
	for _, item := range itens {
		_, err := tx.Exec(`INSERT INTO itens_relatorio (relatorio_id, item_procurado, url_encontrada, status) VALUES ($1, $2, $3, $4)`,
			relatorioId, item.ItemProcurado, item.UrlEncontrada, item.Status)
		if err != nil {
			tx.Rollback()
			return 0, err
		}
	}

	return relatorioId, tx.Commit()
}

func (r *AuditoriaRepository) ListarRelatorios(userId int) ([]map[string]interface{}, error) {
	// 1. Descobre se é Admin
	var isAdmin bool
	err := r.DB.QueryRow("SELECT is_admin FROM usuarios WHERE id = $1", userId).Scan(&isAdmin)
	if err != nil {
		return nil, fmt.Errorf("erro ao verificar permissão: %v", err)
	}

	var query string
	var rows *sql.Rows

	// 2. Define a query baseada no perfil
	if isAdmin {
		query = `
			SELECT r.id, r.codigo, r.url_alvo, to_char(r.data_auditoria, 'DD/MM/YYYY HH24:MI:SS'), u.username
			FROM relatorios r
			JOIN usuarios u ON r.user_id = u.id
			ORDER BY r.data_auditoria DESC
		`
		rows, err = r.DB.Query(query)
	} else {
		query = `
			SELECT r.id, r.codigo, r.url_alvo, to_char(r.data_auditoria, 'DD/MM/YYYY HH24:MI:SS'), u.username
			FROM relatorios r
			JOIN usuarios u ON r.user_id = u.id
			WHERE r.user_id = $1
			ORDER BY r.data_auditoria DESC
		`
		rows, err = r.DB.Query(query, userId)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// 3. Monta a lista de retorno
	var lista []map[string]interface{}
	for rows.Next() {
		var id int
		var codigo, urlAlvo, data, usuario string
		if err := rows.Scan(&id, &codigo, &urlAlvo, &data, &usuario); err != nil {
			continue
		}
		lista = append(lista, map[string]interface{}{
			"id":      id,
			"codigo":  codigo,
			"url":     urlAlvo,
			"data":    data,
			"usuario": usuario,
		})
	}

	// Retorna lista vazia em vez de null se não tiver nada
	if lista == nil {
		lista = []map[string]interface{}{}
	}

	return lista, nil
}

func (r *AuditoriaRepository) GetRelatorioCompleto(id int) (*models.RelatorioFinal, error) {
	var relatorio models.RelatorioFinal

	// 1. Busca Cabeçalho
	queryHeader := `
		SELECT r.id, r.codigo, r.url_alvo, to_char(r.data_auditoria, 'DD/MM/YYYY HH24:MI:SS')
		FROM relatorios r
		WHERE r.id = $1
	`
	err := r.DB.QueryRow(queryHeader, id).Scan(&relatorio.Id, &relatorio.Codigo, &relatorio.UrlAlvo, &relatorio.Data)
	if err != nil {
		return nil, err
	}

	// 2. Busca Itens
	queryItens := `
		SELECT item_procurado, status, coalesce(url_encontrada, '')
		FROM itens_relatorio
		WHERE relatorio_id = $1
	`
	rows, err := r.DB.Query(queryItens, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var item models.ResultadoItem
		rows.Scan(&item.ItemProcurado, &item.Status, &item.UrlEncontrada)
		relatorio.Itens = append(relatorio.Itens, item)
	}

	return &relatorio, nil
}

// ==========================================
// ===       FUNÇÕES DE USUÁRIO           ===
// ==========================================

func (r *AuditoriaRepository) CriarUsuario(username, senhaRaw string) error {
	// Gera o Hash da senha aqui (ou poderia ser no Service, mas aqui garante que nunca salva texto puro)
	hash, err := bcrypt.GenerateFromPassword([]byte(senhaRaw), 10)
	if err != nil {
		return err
	}

	_, err = r.DB.Exec("INSERT INTO usuarios (username, password_hash) VALUES ($1, $2)", username, string(hash))
	return err
}

func (r *AuditoriaRepository) BuscarUsuarioLogin(username, senhaRaw string) (map[string]interface{}, error) {
	var id int
	var hashSalvo, userDb string
	var isAdmin bool

	// 1. Busca o hash no banco
	err := r.DB.QueryRow("SELECT id, username, password_hash, is_admin FROM usuarios WHERE username=$1", username).Scan(&id, &userDb, &hashSalvo, &isAdmin)
	if err != nil {
		return nil, fmt.Errorf("usuário não encontrado")
	}

	// 2. Compara a senha digitada com o hash
	if err := bcrypt.CompareHashAndPassword([]byte(hashSalvo), []byte(senhaRaw)); err != nil {
		return nil, fmt.Errorf("senha incorreta")
	}

	// 3. Retorna os dados seguros
	return map[string]interface{}{
		"id":       id,
		"username": userDb,
		"is_admin": isAdmin,
	}, nil
}

// InicializarTabelas cria a estrutura do banco e o usuário Admin padrão
func (r *AuditoriaRepository) InicializarTabelas() error {
	// 1. Cria Tabela Usuários
	_, err := r.DB.Exec(`CREATE TABLE IF NOT EXISTS usuarios (
		id SERIAL PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		is_admin BOOLEAN DEFAULT FALSE
	);`)
	if err != nil {
		return fmt.Errorf("erro tabela usuarios: %v", err)
	}

	// 2. Cria Admin Padrão
	senhaAdmin := "123"
	hashCalculado, _ := bcrypt.GenerateFromPassword([]byte(senhaAdmin), 10)
	// O 'ON CONFLICT' garante que não duplicará se já existir
	_, err = r.DB.Exec(`INSERT INTO usuarios (id, username, password_hash, is_admin) 
             VALUES (1, 'Auditor Chefe', $1, TRUE) 
             ON CONFLICT (id) DO NOTHING`, string(hashCalculado))
	if err != nil {
		fmt.Println("Erro ao criar admin:", err)
	}

	// 3. Cria Tabela Relatórios
	_, err = r.DB.Exec(`CREATE TABLE IF NOT EXISTS relatorios (
		id SERIAL PRIMARY KEY,
		codigo TEXT UNIQUE NOT NULL,
		user_id INT REFERENCES usuarios(id),
		url_alvo TEXT NOT NULL,
		data_auditoria TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`)
	if err != nil {
		return fmt.Errorf("erro tabela relatorios: %v", err)
	}

	// 4. Cria Tabela Itens
	_, err = r.DB.Exec(`CREATE TABLE IF NOT EXISTS itens_relatorio (
		id SERIAL PRIMARY KEY,
		relatorio_id INT REFERENCES relatorios(id) ON DELETE CASCADE,
		item_procurado TEXT NOT NULL,
		url_encontrada TEXT,
		status TEXT NOT NULL
	);`)
	if err != nil {
		return fmt.Errorf("erro tabela itens: %v", err)
	}

	// 5. Cria Tabela Checklist
	_, err = r.DB.Exec(`CREATE TABLE IF NOT EXISTS checklist (
		id SERIAL PRIMARY KEY,
		termo TEXT UNIQUE NOT NULL
	);`)
	if err != nil {
		return fmt.Errorf("erro tabela checklist: %v", err)
	}

	// 6. Popula Checklist
	itensPadrao := []string{
		"licitacao", "contrato", "despesa", "receita",
		"folha", "diaria", "sic", "ouvidoria",
		"rreo", "rgf", "obra", "diário oficial", "ESTRUTURA ORGANIZACIONAL", "convênio",
	}
	for _, item := range itensPadrao {
		r.DB.Exec(`INSERT INTO checklist (termo) VALUES ($1) ON CONFLICT DO NOTHING`, item)
	}

	fmt.Println(">>> Banco de Dados inicializado e verificado com sucesso!")
	return nil
}
