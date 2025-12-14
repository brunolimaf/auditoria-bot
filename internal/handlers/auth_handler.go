package handlers

import (
	"auditor-bot/internal/services"
	"encoding/json"
	"net/http"
)

type AuthHandler struct {
	Service *services.RoboService // Estamos usando o mesmo service para simplificar
}

func NewAuthHandler(service *services.RoboService) *AuthHandler {
	return &AuthHandler{Service: service}
}

func (h *AuthHandler) Registrar(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Usuario string `json:"usuario"`
		Senha   string `json:"senha"`
	}
	json.NewDecoder(r.Body).Decode(&creds)

	// O Service vai precisar desse método 'RegistrarUsuario' (vamos criar jajá)
	err := h.Service.RegistrarUsuario(creds.Usuario, creds.Senha)
	if err != nil {
		http.Error(w, "Erro ao criar usuário: "+err.Error(), 400)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"msg": "Criado com sucesso"})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Usuario string `json:"usuario"`
		Senha   string `json:"senha"`
	}
	json.NewDecoder(r.Body).Decode(&creds)

	// O Service vai precisar desse método 'AutenticarUsuario'
	usuario, err := h.Service.AutenticarUsuario(creds.Usuario, creds.Senha)
	if err != nil {
		http.Error(w, "Login inválido", 401)
		return
	}

	json.NewEncoder(w).Encode(usuario)
}
