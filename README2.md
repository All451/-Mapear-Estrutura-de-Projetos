
# 🗺️ Mapear Estrutura de Diretórios (Modo Cibersegurança)

> Ferramenta de linha de comando para mapear estrutura de diretórios local ou remoto, útil em pentests, auditorias e análise de superfície de ataque.

---

## 📌 Sobre

O script `mapear_estrutura.sh` é uma ferramenta simples mas poderosa que permite:

- Visualizar a estrutura de pastas e arquivos em formatos como: `tree`, `json`, `markdown` e `plain`.
- Identificar **arquivos sensíveis** (`.env`, chaves SSH, logs, histórico do Bash).
- Detectar **permissões fracas** (`777`, `666`, etc.).
- Útil tanto para documentação de projetos quanto para análise de segurança em sistemas comprometidos ou auditados.

---

## 🛠️ Funcionalidades

| Recurso | Descrição |
|--------|-----------|
| 🔍 **Modo Segurança** (`--security`) | Ativa varredura automática por arquivos sensíveis e permissões fracas |
| 📁 **Suporta múltiplos formatos** | tree (padrão), json, markdown, plain |
| 🧠 **Ignora padrões personalizados** | Com base no `.mapignore` |
| 🕵️‍♂️ **Arquivos ocultos** | Mostra arquivos iniciados com `.` |
| 🔐 **Permissões dos arquivos** | Mostra permissões Linux (`-rwxrwxrwx`) |
| 📏 **Tamanhos dos arquivos** | Exibe tamanho em bytes |
| 📥 **Exporta para arquivo** | Salva saída em qualquer formato suportado |

---

## ⚙️ Requisitos

Antes de executar o script, instale as dependências necessárias:

```bash
sudo apt update && sudo apt install tree -y
sudo apt install jq -y  # Opcional, necessário para JSON
```

---

## 📦 Instalação

1. Dê permissão de execução:

```bash
chmod +x mapear_estrutura.sh
```

2. Execute diretamente:

```bash
./mapear_estrutura.sh [opções] [diretório]
```

---

## 🧪 Uso Básico

### Mapear estrutura atual

```bash
./mapear_estrutura.sh .
```

### Mapear diretório específico

```bash
./mapear_estrutura.sh /home/usuario/projeto
```

### Mapear com modo segurança (recomendado em pentests)

```bash
./mapear_estrutura.sh --security -s -p -a /home/usuario/
```

### Exportar para Markdown

```bash
./mapear_estrutura.sh --security -f markdown /etc > relatorio_etc.md
```

### Exportar para JSON

```bash
./mapear_estrutura.sh --security -f json /var/www > analise.json
```

---

## 🧭 Opções Disponíveis

| Opção | Descrição |
|-------|-----------|
| `-l NIVEL`, `--level NIVEL` | Limita profundidade da árvore |
| `-o ARQUIVO`, `--output ARQUIVO` | Salva saída em arquivo |
| `-f FORMATO`, `--format FORMATO` | Formato de saída (`tree`, `json`, `markdown`, `plain`) |
| `-v`, `--verbose` | Modo verboso (mostra logs detalhados) |
| `-h`, `--help` | Mostra ajuda |
| `-V`, `--version` | Mostra versão |
| `-a`, `--all` | Inclui arquivos ocultos |
| `-s`, `--size` | Mostra tamanhos dos arquivos |
| `-d`, `--dirs-only` | Mostra apenas diretórios |
| `-C`, `--no-color` | Desativa cores na saída |
| `-p`, `--permissions` | Mostra permissões dos arquivos |
| `-i ARQUIVO`, `--ignore-file ARQUIVO` | Define arquivo `.mapignore` personalizado |
| `--security` | Ativa modo de análise de segurança (busca arquivos sensíveis e permissões fracas) |

---

## 📁 Arquivo `.mapignore`

Você pode criar um arquivo chamado `.mapignore` no diretório alvo para especificar quais pastas/arquivos devem ser ignorados.

Exemplo de conteúdo:

```
node_modules
.git
__pycache__
*.log
.env
```

---

## 🧠 Exemplos Práticos

### Buscar arquivos sensíveis em `/home`

```bash
./mapear_estrutura.sh --security -a /home
```

### Mapear diretório raiz com profundidade limitada

```bash
sudo ./mapear_estrutura.sh --security -l 2 / > mapeamento_root.txt
```

### Usar remotamente via SSH

```bash
ssh usuario@ip_remoto "./mapear_estrutura.sh --security -f markdown /home/usuario/" > relatorio_remoto.md
```

---

## 📊 Saída de Exemplo (Markdown)

```markdown
# Estrutura do Diretório

Gerado em: Sat Jul 12 18:00:00 UTC 2025  
Diretório: /home/usuario/

```
/home/usuario/
├── .bashrc
├── .ssh
│   └── id_rsa
├── documentos
│   └── config.php
└── logs
    └── acesso.log
```

## 🔍 Arquivos Sensíveis Encontrados
```
/home/usuario/.ssh/id_rsa
/home/usuario/documentos/config.php
/home/usuario/logs/acesso.log
```

## 🔒 Permissões Fracas Encontradas
-rw-rw-rw- 1 usuario usuario  3456 Jan  1  2020 /home/usuario/logs/acesso.log
```

---

## 📝 Versão

Versão atual: `1.0`  
Data: `Julho de 2025`  
Autor: *Sistema de Mapeamento de Estruturas*  
Licença: MIT

---

## 💬 Feedback & Contribuição

Contribuições são bem-vindas! Se você tem ideias para melhorar o script ou adicionar novas funcionalidades, fique à vontade para abrir uma issue ou PR no repositório.

