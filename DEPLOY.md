# Águia Tracker — Guia de Deploy

## O que é

Sistema completo de rastreamento de cliques, visitas e conversões para afiliados.
- Backend Node.js + Express
- Banco de dados SQLite (persiste no servidor)
- Script de tracking real (pixel 1x1)
- Postback para BuyGoods, MaxWeb, Digistore24, etc.
- Dashboard com dados reais
- Geolocalização por IP (país, cidade, região)
- Detecção de device/browser/OS

---

## Deploy GRATUITO no Railway

### Passo 1: Criar conta no Railway
1. Acesse https://railway.com
2. Crie uma conta com GitHub (grátis)

### Passo 2: Subir o projeto
1. Crie um repositório no GitHub com estes arquivos
2. No Railway, clique "New Project" → "Deploy from GitHub repo"
3. Selecione o repositório

### Passo 3: Configurar
O Railway vai detectar o Dockerfile automaticamente.
Adicione a variável de ambiente:
- `JWT_SECRET` = uma string aleatória longa (ex: gere em https://randomkeygen.com)

### Passo 4: Domínio
O Railway gera um domínio tipo `aguia-tracker-production.up.railway.app`
Você pode adicionar um domínio próprio nas configurações.

---

## Como usar

### 1. Criar conta
Acesse o dashboard e crie uma conta (email + senha).

### 2. Criar TAG
No dashboard, vá em "TAG Águia" e crie uma nova TAG.

### 3. Instalar o script
Clique em "Instalar" na TAG criada.
Copie o script gerado e cole nas suas páginas (antes do `</head>`).

### 4. Configurar Postback (BuyGoods, MaxWeb, etc.)
Use a URL de postback na plataforma de afiliados:

```
https://SEU-DOMINIO/postback/SEU_TAG_ID?amount={amount}&vid={click_id}&network=buygoods&offer={offer_id}
```

Parâmetros aceitos:
- `amount` ou `revenue` — valor da venda
- `vid` ou `clickid` — ID do visitante
- `offer` — nome/ID da oferta
- `txid` — ID da transação
- `network` — nome da rede (buygoods, maxweb, etc.)
- `ip` — IP do comprador (opcional, para geolocalização)

### 5. Ver dados
O dashboard mostra em tempo real:
- Visitas por país/cidade
- Cliques
- Conversões
- Receita
- Device/Browser/OS
- Horário das visitas

---

## Rodar localmente

```bash
npm install
node server.js
```

Acesse http://localhost:3000

---

## Alternativas gratuitas de hospedagem

| Plataforma | Plano Grátis | Observação |
|------------|-------------|------------|
| Railway    | $5 crédito/mês | Recomendado |
| Render     | 750h/mês grátis | Dorme após 15min inativo |
| Fly.io     | 3 VMs grátis | Bom mas config mais complexa |
| Oracle Cloud | Always Free | VPS grátis permanente |

---

## Estrutura

```
aguia-tracker/
├── server.js          # Backend Express + SQLite + API
├── public/
│   └── index.html     # Dashboard completo
├── data/
│   └── aguia.db       # Banco de dados (criado automaticamente)
├── package.json
├── Dockerfile
├── railway.toml
└── DEPLOY.md
```
