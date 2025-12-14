package handlers

import (
	"auditor-bot/internal/services"
	"encoding/json"
	"net/http"
	"strconv"
)

type RelatorioHandler struct {
	Service *services.RoboService
}

func NewRelatorioHandler(service *services.RoboService) *RelatorioHandler {
	return &RelatorioHandler{Service: service}
}

func (h *RelatorioHandler) ListarHistorico(w http.ResponseWriter, r *http.Request) {
	userIdStr := r.URL.Query().Get("user_id")
	userId, _ := strconv.Atoi(userIdStr)

	// O Service vai precisar desse método 'ListarHistorico'
	lista, err := h.Service.ListarHistorico(userId)
	if err != nil {
		http.Error(w, "Erro ao buscar histórico", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(lista)
}

func (h *RelatorioHandler) Detalhes(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, _ := strconv.Atoi(idStr)

	// O Service vai precisar desse método 'ObterDetalhesRelatorio'
	relatorio, err := h.Service.ObterDetalhesRelatorio(id)
	if err != nil {
		http.Error(w, "Relatório não encontrado", 404)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(relatorio)
}
