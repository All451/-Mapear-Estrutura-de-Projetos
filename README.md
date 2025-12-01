# 🗺️ Mapear Estrutura de Diretórios (Biblioteca Profissional)

> Biblioteca de utilitário para mapeamento de estrutura de diretórios com funcionalidades de segurança integradas

## 📌 Sobre

A biblioteca `libmapear.sh` é uma solução profissional para mapeamento de estrutura de diretórios, desenvolvida com as melhores práticas de engenharia de software. Oferece:

- **Modularidade**: Código organizado em uma biblioteca reutilizável
- **Segurança**: Detecção de arquivos sensíveis e permissões fracas
- **Flexibilidade**: Múltiplos formatos de saída (tree, JSON, Markdown, plain)
- **Profissionalismo**: Código limpo, documentado e testável

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
| 🏗️ **Arquitetura modular** | Código separado em biblioteca e interface de usuário |

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
chmod +x mapear_estrutura.sh libmapear.sh
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
```

---

## 🏗️ Arquitetura do Projeto

```
mapear_estrutura.sh     # Interface de linha de comando
├── libmapear.sh        # Biblioteca de funções
    ├── log()           # Sistema de logging
    ├── verificar_dependencias()  # Verificação de requisitos
    ├── ler_mapignore() # Leitura de padrões de ignore
    ├── gerar_json()    # Formato JSON
    ├── gerar_markdown() # Formato Markdown
    ├── gerar_plain()   # Formato texto simples
    ├── buscar_arquivos_sensiveis() # Busca de arquivos sensíveis
    ├── buscar_permissoes_fracas() # Busca de permissões fracas
    └── mapear_estrutura() # Função principal
```

---

## 📝 Versão

Versão atual: `3.0`  
Data: `Dezembro de 2025`  
Autor: *Sistema de Mapeamento de Estruturas*  
Licença: MIT

---

## 💬 Utilizando como Biblioteca

Você pode importar a biblioteca em seus próprios scripts Bash:

```bash
#!/bin/bash
source "./libmapear.sh"

# Agora você pode usar as funções diretamente
PADROES_IGNORE=$(ler_mapignore ".mapignore")
mapear_estrutura "/caminho/diretorio" "$PADROES_IGNORE" "false"
```

---

## 💡 Dicas Profissionais

- Use `-v` para depurar problemas durante execução.
- Combine com CI/CD para gerar documentação automaticamente.
- Mantenha o `.mapignore` atualizado para evitar excessos na saída.
- Utilize o modo segurança (`--security`) em ambientes de segurança.
- Exporte para JSON para integração com outras ferramentas.

---

## 🛠️ Contribuição

Contribuições são bem-vindas! Se você tem ideias para melhorar a biblioteca ou adicionar novas funcionalidades, fique à vontade para abrir uma issue ou PR no repositório.

### Melhorias Futuras Planejadas
- Suporte para exportar para XML
- Integração com APIs REST
- Sistema de plugins para funcionalidades adicionais
- Testes automatizados
- Validação de entrada mais robusta

