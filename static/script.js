// Variável global para guardar o relatório atual
let dadosRelatorioAtual = null;

// =========================================================
// 1. INICIALIZAÇÃO E EVENTOS
// =========================================================

document.addEventListener("DOMContentLoaded", () => {
    const userId = localStorage.getItem('user_id');
    const username = localStorage.getItem('username');

    if (userId) {
        exibirSistemaPrincipal(username);
    } else {
        exibirTelaLogin();
    }

    // Tecla Enter no Login
    configurarEnter('userLogin', fazerLogin);
    configurarEnter('passLogin', fazerLogin);
    
    // Tecla Enter na Nova Auditoria
    configurarEnter('urlInput', executarAuditoria);
});

function configuringEnter(idInput, funcao) {
    const input = document.getElementById(idInput);
    if(input) {
        input.addEventListener("keypress", (e) => {
            if (e.key === "Enter") { e.preventDefault(); funcao(); }
        });
    }
}

function configurarEnter(id, func) {
    const elem = document.getElementById(id);
    if(elem) elem.addEventListener("keypress", (e) => { if(e.key === 'Enter') func(); });
}

// =========================================================
// 2. GESTÃO DE TELAS
// =========================================================

function exibirTelaLogin() {
    document.getElementById('tela-login').classList.remove('hidden');
    document.getElementById('sistema-principal').classList.add('hidden');
}

function exibirSistemaPrincipal(nomeUsuario) {
    document.getElementById('tela-login').classList.add('hidden');
    document.getElementById('sistema-principal').classList.remove('hidden');
    document.getElementById('header-user').innerText = nomeUsuario || 'Auditor';
    voltarDashboard();
}

function trocarView(idView) {
    const views = ['view-dashboard', 'view-nova', 'view-detalhes', 'view-resultado'];
    views.forEach(v => {
        const el = document.getElementById(v);
        if(el) {
            el.classList.add('hidden');
            el.style.display = 'none';
        }
    });

    const alvo = document.getElementById(idView);
    if(alvo) {
        alvo.classList.remove('hidden');
        alvo.style.display = 'block';
    }
}

function sair() {
    localStorage.clear();
    exibirTelaLogin();
}

// =========================================================
// 3. AUTENTICAÇÃO
// =========================================================

function alternarModoLogin() {
    const btnEntrar = document.getElementById('btn-entrar');
    const btnCadastrar = document.getElementById('btn-cadastrar');
    const titulo = document.getElementById('titulo-login');
    const msg = document.getElementById('msg-troca');

    if (btnEntrar.classList.contains('hidden')) {
        btnEntrar.classList.remove('hidden');
        btnCadastrar.classList.add('hidden');
        titulo.innerText = "🔐 SIA Auditoria";
        msg.innerText = "Não tem conta?";
    } else {
        btnEntrar.classList.add('hidden');
        btnCadastrar.classList.remove('hidden');
        titulo.innerText = "📝 Novo Auditor";
        msg.innerText = "Já tem conta?";
    }
    document.getElementById('erro-login').innerText = "";
}

async function fazerLogin() {
    const usuario = document.getElementById('userLogin').value;
    const senha = document.getElementById('passLogin').value;
    const erroMsg = document.getElementById('erro-login');

    if (!usuario || !senha) return erroMsg.innerText = "Preencha todos os campos.";

    try {
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usuario, senha })
        });

        if (!res.ok) throw new Error("Usuário ou senha incorretos.");

        const dados = await res.json();
        localStorage.setItem('user_id', dados.id);
        localStorage.setItem('username', dados.username);
        localStorage.setItem('is_admin', dados.is_admin);

        exibirSistemaPrincipal(dados.username);

    } catch (e) {
        erroMsg.innerText = e.message;
    }
}

async function registrar() {
    const usuario = document.getElementById('userLogin').value;
    const senha = document.getElementById('passLogin').value;
    const erroMsg = document.getElementById('erro-login');

    if (!usuario || !senha) return erroMsg.innerText = "Preencha todos os campos.";

    try {
        const res = await fetch('/api/registrar', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usuario, senha })
        });

        if (!res.ok) throw new Error("Erro ao criar.");

        alert("Conta criada! Faça login agora.");
        alternarModoLogin();

    } catch (e) {
        erroMsg.innerText = e.message;
    }
}

// =========================================================
// 4. HISTÓRICO E DASHBOARD
// =========================================================

async function voltarDashboard() {
    trocarView('view-dashboard');
    const tbody = document.getElementById('lista-relatorios');
    const userId = localStorage.getItem('user_id');

    tbody.innerHTML = '<tr><td colspan="5">Carregando histórico...</td></tr>';

    try {
        const res = await fetch(`/api/historico?user_id=${userId}`);
        const lista = await res.json();

        tbody.innerHTML = '';
        if(lista.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5">Nenhuma auditoria realizada.</td></tr>';
            return;
        }

        lista.forEach(r => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${r.codigo}</strong></td>
                <td>${r.data}</td>
                <td><a href="${r.url}" target="_blank">${r.url}</a></td>
                <td>${r.usuario}</td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="carregarDetalhes(${r.id})">Ver</button>
                </td>
            `;
            tbody.appendChild(tr);
        });

    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="5">Erro de conexão.</td></tr>';
    }
}

async function carregarDetalhes(id) {
    try {
        const res = await fetch(`/api/relatorio?id=${id}`);
        const dados = await res.json();
        dadosRelatorioAtual = dados; 
        renderizarTelaResultado(dados);
        trocarView('view-resultado');
    } catch (e) {
        alert("Erro ao carregar detalhes.");
    }
}

// =========================================================
// 5. NOVA AUDITORIA (ROBÔ)
// =========================================================

// --- FIX DO BOTÃO "NOVA AUDITORIA" ---
// O seu HTML chama 'novaAuditoria()', mas a lógica estava em 'irNovaAuditoria()'
// Vamos garantir que ambos funcionem.
function novaAuditoria() {
    irNovaAuditoria();
}

function irNovaAuditoria() {
    document.getElementById('urlInput').value = ''; // Limpa o campo
    document.getElementById('loading').classList.add('hidden'); 
    document.getElementById('loading').style.display = 'none';
    
    // Limpa resultados anteriores visualmente
    document.getElementById('res-itens').innerHTML = '';
    
    trocarView('view-nova');
    
    // Foca no campo para digitar logo
    setTimeout(() => document.getElementById('urlInput').focus(), 100);
}

async function executarAuditoria() {
    const url = document.getElementById('urlInput').value;
    const userId = localStorage.getItem('user_id');

    if (!url) return alert("Digite a URL!");

    const loading = document.getElementById('loading');
    loading.classList.remove('hidden');
    loading.style.display = 'block';

    try {
        const res = await fetch('/api/auditar', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url, user_id: parseInt(userId) })
        });

        if (!res.ok) throw new Error("Falha na auditoria.");

        const dados = await res.json();
        dadosRelatorioAtual = dados;
        
        renderizarTelaResultado(dados);
        trocarView('view-resultado');

    } catch (e) {
        alert("Erro: " + e.message);
    } finally {
        loading.classList.add('hidden');
        loading.style.display = 'none';
    }
}

function renderizarTelaResultado(dados) {
  const header = document.getElementById('res-cabecalho');
  
  // FIX 1: Pegamos a URL correta que veio do Back-end (Go)
  // Ela já vem com https://, garantindo que não dê erro de localhost
  const urlFull = dados.url_alvo; 

  // FIX 2: Criamos uma versão "limpa" apenas para EXIBIÇÃO (Texto bonito)
  // Removemos 'https://' e 'www.' visualmente, mas mantemos no link real
  let urlVisual = urlFull.replace(/^https?:\/\//, '').replace(/^www\./, '');
  // Remove a barra no final se tiver
  if (urlVisual.endsWith('/')) urlVisual = urlVisual.slice(0, -1);

  header.innerHTML = `
      <strong>Código:</strong> ${dados.codigo} <span style="margin:0 10px">|</span>
      <strong>Site:</strong> <a href="${urlFull}" target="_blank" style="color: #3498db; text-decoration: underline;">${urlVisual}</a> <span style="margin:0 10px">|</span>
      <strong>Data:</strong> ${dados.data}
  `;

  const grid = document.getElementById('res-itens');
  grid.innerHTML = '';

  dados.itens.forEach(item => {
      const div = document.createElement('div');
      div.className = `result-item ${item.status === 'ENCONTRADO' ? 'encontrado' : 'ausente'}`;

      if(item.status === 'ENCONTRADO') {
          div.style.borderLeft = "5px solid #27ae60";
          div.style.backgroundColor = "#eafaf1";
      } else {
          div.style.borderLeft = "5px solid #c0392b";
          div.style.backgroundColor = "#fadbd8";
      }
      div.style.padding = "10px";
      div.style.margin = "5px";
      div.style.borderRadius = "4px";
      
      let html = `<strong>${item.item_procurado.toUpperCase()}</strong><br>`;
      if (item.status === 'ENCONTRADO') {
          html += `<span style="color:green; font-weight:bold">✓ ENCONTRADO</span><br>`;
          html += `<a href="${item.url_encontrada}" target="_blank" style="font-size:0.8em">Abrir Link</a>`;
      } else {
          html += `<span style="color:red; font-weight:bold">✕ AUSENTE</span>`;
      }
      div.innerHTML = html;
      grid.appendChild(div);
  });
}

// =========================================================
// 6. PARECER TÉCNICO
// =========================================================

function gerarParecerTecnico() {
    if (!dadosRelatorioAtual) return;

    // --- FIX DA URL NO PARECER ---
    const urlCompleta = dadosRelatorioAtual.url_alvo; // URL inteira (https://...)
    const data = dadosRelatorioAtual.data;
    const codigo = dadosRelatorioAtual.codigo;
    
    // Lógica para extrair só o nome do município (para a sugestão do subdomínio)
    let municipio = "municipio";
    try {
        const urlObj = new URL(urlCompleta.startsWith('http') ? urlCompleta : 'https://' + urlCompleta);
        const parts = urlObj.hostname.split('.');
        const ignore = ['www', 'gov', 'br', 'ba', 'sp', 'mg', 'rj'];
        const candidates = parts.filter(p => !ignore.includes(p));
        if (candidates.length > 0) municipio = candidates[0];
    } catch (e) {}

    const itensAusentes = dadosRelatorioAtual.itens.filter(i => i.status === 'AUSENTE');
    const listaAusentes = itensAusentes.map(i => `- ${i.item_procurado.toUpperCase()}`).join('\n');

    const texto = `
PARECER TÉCNICO DE AUDITORIA DE TI Nº ${codigo}
DATA: ${data}
OBJETO: Verificação de Disponibilidade de Itens de Transparência Ativa
SÍTIO AUDITADO: ${urlCompleta}

1. RELATÓRIO DE CONSTATAÇÃO
Em procedimento de auditoria automatizada realizado na data supra, utilizando-se da ferramenta SIA, constatou-se a indisponibilidade ou a dificuldade de acesso aos seguintes instrumentos obrigatórios (LC 101/2000 e Lei 12.527/2011):

${listaAusentes || "NENHUM ITEM AUSENTE CONSTATADO."}

2. ANÁLISE TÉCNICA E RECOMENDAÇÕES
A ausência de indexação e acesso direto compromete a Transparência Ativa. Sugere-se a notificação do Gestor Responsável para:

I - Correção imediata dos links quebrados ou inexistentes;
II - Padronização de domínios conforme e-PING, criando (caso não exista) o endereço dedicado:
    > https://transparencia.${municipio}.ba.gov.br
    
3. CONCLUSÃO
Este relatório serve como base para abertura de Processo de Fiscalização.

_______________________________
AUDITORIA DE INFRAESTRUTURA
SISTEMA SIA - TCM/BA
`.trim();

    document.getElementById('texto-parecer').value = texto;
    document.getElementById('modal-parecer').style.display = 'block';
}

function fecharModal() {
    document.getElementById('modal-parecer').style.display = 'none';
}

function copiarParecer() {
    const textarea = document.getElementById('texto-parecer');
    textarea.select();
    document.execCommand('copy');
    alert("Copiado!");
}

window.onclick = function(event) {
    const modal = document.getElementById('modal-parecer');
    if (event.target == modal) {
        modal.style.display = "none";
    }
}