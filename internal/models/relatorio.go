package models

// ResultadoItem representa um item auditado (ex: encontrou "licitações")
type ResultadoItem struct {
	ItemProcurado string `json:"item_procurado"`
	Status        string `json:"status"`
	UrlEncontrada string `json:"url_encontrada"`
}

// RelatorioFinal é o documento completo da auditoria
type RelatorioFinal struct {
	Id      int             `json:"id"`
	Codigo  string          `json:"codigo"`
	UrlAlvo string          `json:"url_alvo"`
	Data    string          `json:"data"`
	Itens   []ResultadoItem `json:"itens"`
}

// Credenciais para login
type Credenciais struct {
	Usuario string `json:"usuario"`
	Senha   string `json:"senha"`
}
