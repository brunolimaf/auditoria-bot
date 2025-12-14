package handlers

import (
	"auditor-bot/internal/services"
	"encoding/json"
	"net/http"
)

type AuditoriaHandler struct {
	Service *services.RoboService
}

func NewAuditoriaHandler(service *services.RoboService) *AuditoriaHandler {
	return &AuditoriaHandler{Service: service}
}

// Auditar é a função que o main vai chamar na rota /api/auditar
func (h *AuditoriaHandler) Auditar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método inválido", 405)
		return
	}

	var reqData struct {
		Url    string `json:"url"`
		UserId int    `json:"user_id"`
	}
	json.NewDecoder(r.Body).Decode(&reqData)

	// Chama o Service
	relatorio, err := h.Service.ExecutarAuditoria(reqData.Url, reqData.UserId)
	if err != nil {
		http.Error(w, "Erro na auditoria: "+err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(relatorio)
}
