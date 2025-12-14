package services

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"auditor-bot/internal/models"
	"auditor-bot/internal/repositories"

	"github.com/PuerkitoBio/goquery"
)

type RoboService struct {
	Repo *repositories.AuditoriaRepository
}

func NewRoboService(repo *repositories.AuditoriaRepository) *RoboService {
	return &RoboService{Repo: repo}
}

// === MÉTODOS DE AUTENTICAÇÃO E HISTÓRICO (Mantidos) ===
func (s *RoboService) RegistrarUsuario(user, senha string) error {
	return s.Repo.CriarUsuario(user, senha)
}
func (s *RoboService) AutenticarUsuario(user, senha string) (map[string]interface{}, error) {
	return s.Repo.BuscarUsuarioLogin(user, senha)
}
func (s *RoboService) ListarHistorico(userId int) ([]map[string]interface{}, error) {
	return s.Repo.ListarRelatorios(userId)
}
func (s *RoboService) ObterDetalhesRelatorio(id int) (*models.RelatorioFinal, error) {
	return s.Repo.GetRelatorioCompleto(id)
}

// === MÉTODOS DE AUDITORIA ===

func (s *RoboService) ExecutarAuditoria(urlAlvo string, userId int) (*models.RelatorioFinal, error) {
	// 1. Pega termos
	termos, err := s.Repo.GetChecklist()
	if err != nil {
		return nil, err
	}
	fmt.Printf("📋 Checklist carregado: %d termos para procurar.\n", len(termos))

	// 2. Auditoria
	itensResultado, err := s.realizarAuditoriaProfunda(urlAlvo, termos)
	if err != nil {
		return nil, err
	}

	// 3. Salva
	codigo := s.gerarCodigo()
	id, err := s.Repo.SalvarRelatorio(userId, urlAlvo, codigo, itensResultado)
	if err != nil {
		return nil, err
	}

	return &models.RelatorioFinal{
		Id:      id,
		Codigo:  codigo,
		UrlAlvo: urlAlvo,
		Data:    time.Now().Format("02/01/2006 15:04:05"),
		Itens:   itensResultado,
	}, nil
}

func (s *RoboService) realizarAuditoriaProfunda(urlPrincipal string, termos []string) ([]models.ResultadoItem, error) {
	mapaResultados := make(map[string]models.ResultadoItem)
	for _, t := range termos {
		mapaResultados[t] = models.ResultadoItem{ItemProcurado: t, Status: "AUSENTE", UrlEncontrada: ""}
	}

	urlsParaEscanear := s.descobrirPortais(urlPrincipal)
	fmt.Println("🌍 Portais para analisar:", urlsParaEscanear)

	fila := urlsParaEscanear
	visitadas := make(map[string]bool)
	var mu sync.Mutex

	limitePaginas := 25
	contador := 0

	for len(fila) > 0 && contador < limitePaginas {
		urlAlvo := fila[0]
		fila = fila[1:]

		if visitadas[urlAlvo] {
			continue
		}
		visitadas[urlAlvo] = true
		contador++

		fmt.Printf("--> [%d/%d] Acessando: %s ... ", contador, limitePaginas, urlAlvo)

		doc, err := s.baixarHTML(urlAlvo)
		if err != nil {
			fmt.Printf("❌ ERRO: %v\n", err)
			continue
		}

		// Debug: Mostra o título da página para ver se baixou certo
		titulo := doc.Find("title").Text()
		fmt.Printf("✅ OK (Título: %s)\n", strings.TrimSpace(titulo))

		novasUrls := s.analisarDocumento(doc, urlAlvo, termos, mapaResultados, &mu)

		for _, nova := range novasUrls {
			if !visitadas[nova] {
				fila = append(fila, nova)
			}
		}
	}

	var listaFinal []models.ResultadoItem
	for _, t := range termos {
		item := mapaResultados[t]
		// Debug simples
		if item.Status == "ENCONTRADO" {
			fmt.Printf("   🎉 ACHOU: %s em %s\n", item.ItemProcurado, item.UrlEncontrada)
		}
		listaFinal = append(listaFinal, item)
	}
	return listaFinal, nil
}

func (s *RoboService) analisarDocumento(doc *goquery.Document, urlAtual string, termos []string, mapa map[string]models.ResultadoItem, mu *sync.Mutex) []string {
	baseUrl, _ := url.Parse(urlAtual)
	var linksInteressantes []string
	totalLinks := 0

	processarLink := func(linkRaw string, textoContexto string) {
		linkFinal := linkRaw
		hrefUrl, err := url.Parse(linkRaw)
		if err == nil && baseUrl != nil {
			linkFinal = baseUrl.ResolveReference(hrefUrl).String()
		}

		// Normaliza para comparação
		textoContextoLower := strings.ToLower(textoContexto)
		linkFinalLower := strings.ToLower(linkFinal)

		for _, termo := range termos {
			mu.Lock()
			jaAchou := mapa[termo].Status == "ENCONTRADO"
			mu.Unlock()

			if jaAchou {
				continue
			}

			// Verifica se o termo está no texto OU no link
			if strings.Contains(textoContextoLower, termo) || strings.Contains(linkFinalLower, termo) {
				mu.Lock()
				mapa[termo] = models.ResultadoItem{
					ItemProcurado: termo,
					Status:        "ENCONTRADO",
					UrlEncontrada: linkFinal,
				}
				mu.Unlock()
			}
		}

		gatilhos := []string{"transparência", "transparencia", "portal", "acesso a informação", "ouvidoria"}
		ehArquivo := strings.HasSuffix(linkFinalLower, ".pdf") || strings.HasSuffix(linkFinalLower, ".zip")

		if !ehArquivo {
			for _, gatilho := range gatilhos {
				if strings.Contains(textoContextoLower, gatilho) {
					linksInteressantes = append(linksInteressantes, linkFinal)
					break
				}
			}
		}
	}

	doc.Find("a").Each(func(i int, sel *goquery.Selection) {
		href, exists := sel.Attr("href")
		if !exists {
			return
		}
		totalLinks++
		texto := s.extrairTextoRico(sel)
		processarLink(href, texto)
	})

	doc.Find("iframe").Each(func(i int, sel *goquery.Selection) {
		src, exists := sel.Attr("src")
		if !exists {
			return
		}
		processarLink(src, "iframe transparencia sistema externo")
		linksInteressantes = append(linksInteressantes, src)
	})

	// fmt.Printf("   (Encontrou %d links nesta página)\n", totalLinks) // Descomente se quiser muito detalhe
	return linksInteressantes
}

func (s *RoboService) extrairTextoRico(sel *goquery.Selection) string {
	texto := sel.Text()
	title, _ := sel.Attr("title")
	img := sel.Find("img")
	alt := img.AttrOr("alt", "")
	imgTitle := img.AttrOr("title", "")
	// Junta tudo
	return fmt.Sprintf("%s %s %s %s", texto, title, alt, imgTitle)
}

func (s *RoboService) baixarHTML(urlAlvo string) (*goquery.Document, error) {
	// Melhorei o Client para aceitar TLS antigo (comum em governo)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10, // Aceita TLS antigo
			CipherSuites:       nil,              // Aceita tudo
		},
	}
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second}

	req, _ := http.NewRequest("GET", urlAlvo, nil)

	// Headers completos para fingir ser um Chrome no Windows
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("status HTTP %d", res.StatusCode)
	}

	return goquery.NewDocumentFromReader(res.Body)
}

func (s *RoboService) descobrirPortais(urlEntrada string) []string {
	// 1. Limpeza básica
	urlEntrada = strings.TrimSpace(strings.ToLower(urlEntrada))

	// 2. INTEELIGÊNCIA DE AUTO-COMPLETE (Bahia)
	// Se o usuário digitou apenas "salvador" (sem pontos), assumimos que é uma prefeitura da BA
	if !strings.Contains(urlEntrada, ".") {
		// Transforma "salvador" em "www.salvador.ba.gov.br"
		// Adicionamos o 'www' porque é o padrão mais comum para o site principal
		urlEntrada = "www." + urlEntrada + ".ba.gov.br"
		fmt.Println("✨ Auto-complete ativado: Transformando em", urlEntrada)
	}

	// 3. Garante o Protocolo HTTPS
	if !strings.HasPrefix(urlEntrada, "http") {
		urlEntrada = "https://" + urlEntrada
	}

	// 4. Parse da URL (agora garantida estar correta)
	u, err := url.Parse(urlEntrada)
	if err != nil {
		// Se mesmo assim falhar, retorna o que tem
		return []string{urlEntrada}
	}

	host := u.Hostname()
	scheme := u.Scheme

	// Remove o www. para gerar os subdomínios limpos (ex: transparencia.salvador...)
	hostRaiz := strings.TrimPrefix(host, "www.")

	// Lista de candidatos
	candidatos := []string{
		urlEntrada, // A URL principal (ex: https://www.salvador.ba.gov.br)

		// Variações de Subdomínio
		fmt.Sprintf("%s://transparencia.%s", scheme, hostRaiz),
		fmt.Sprintf("%s://portaldatransparencia.%s", scheme, hostRaiz),
		fmt.Sprintf("%s://portal.%s", scheme, hostRaiz),
		fmt.Sprintf("%s://esic.%s", scheme, hostRaiz),

		// Variações de Caminho (Path)
		strings.TrimRight(urlEntrada, "/") + "/transparencia",
		strings.TrimRight(urlEntrada, "/") + "/portal",
		strings.TrimRight(urlEntrada, "/") + "/ouvidoria",
		strings.TrimRight(urlEntrada, "/") + "/acessoainformacao",

		// Tentativa direta sem www (algumas prefeituras configuram mal o DNS do www)
		fmt.Sprintf("%s://%s", scheme, hostRaiz),
	}

	var urlsValidas []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Testa em paralelo
	for _, c := range candidatos {
		wg.Add(1)
		go func(teste string) {
			defer wg.Done()

			tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
			client := &http.Client{Transport: tr, Timeout: 6 * time.Second} // Aumentei 1s para garantir

			resp, err := client.Get(teste)
			if err == nil && resp.StatusCode < 500 {
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

func (s *RoboService) gerarCodigo() string {
	ano := time.Now().Year()
	letras := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	l1 := string(letras[rand.Intn(len(letras))])
	l2 := string(letras[rand.Intn(len(letras))])
	numeros := rand.Intn(10000)
	return fmt.Sprintf("%d%s%s%04d", ano, l1, l2, numeros)
}
