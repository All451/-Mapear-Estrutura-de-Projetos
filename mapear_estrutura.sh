#!/bin/bash
# script: mapear_estrutura.sh
# Versão: 1.2
# Uso: ./mapear_estrutura.sh [opções] [caminho_do_projeto]
# Autor: Sistema de Mapeamento de Estruturas

set -euo pipefail

# Configurações padrão
PROJETO_DIR="."
NIVEL=""
ARQ_SAIDA=""
FORMATO="tree"
VERBOSE=false
MOSTRAR_AJUDA=false
MOSTRAR_VERSAO=false
INCLUIR_ARQUIVOS_OCULTOS=false
MOSTRAR_TAMANHOS=false
APENAS_DIRETORIOS=false
COLORIR_SAIDA=true
INCLUIR_PERMISSOES=false
ARQUIVO_MAPIGNORE=".mapignore"
VERSAO="2.2"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função para logging
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")
            [ "$VERBOSE" = true ] && echo -e "${GREEN}[INFO]${NC} $timestamp - $message" >&2
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $timestamp - $message" >&2
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $timestamp - $message" >&2
            ;;
        "DEBUG")
            [ "$VERBOSE" = true ] && echo -e "${BLUE}[DEBUG]${NC} $timestamp - $message" >&2
            ;;
    esac
}

# Função para mostrar ajuda
mostrar_ajuda() {
    cat << EOF
${GREEN}Mapear Estrutura de Projetos v${VERSAO}${NC}

${BLUE}USO:${NC}
    \$0 [OPÇÕES] [CAMINHO_DO_PROJETO]

${BLUE}OPÇÕES:${NC}
    -l, --level NIVEL          Limita a profundidade do mapeamento
    -o, --output ARQUIVO       Salva a saída em um arquivo
    -f, --format FORMATO       Formato de saída (tree, json, markdown, plain)
    -v, --verbose              Modo verboso (mostra logs detalhados)
    -h, --help                 Mostra esta ajuda
    -V, --version              Mostra a versão
    -a, --all                  Inclui arquivos ocultos (começados com .)
    -s, --size                 Mostra o tamanho dos arquivos
    -d, --dirs-only            Mostra apenas diretórios
    -C, --no-color             Desabilita cores na saída
    -p, --permissions          Mostra permissões dos arquivos
    -i, --ignore-file ARQUIVO  Especifica arquivo de ignore personalizado

${BLUE}EXEMPLOS:${NC}
    \$0                                    # Mapeia diretório atual
    \$0 /caminho/projeto                   # Mapeia projeto específico
    \$0 -l 3 -o estrutura.txt ~/projeto   # Mapeia até 3 níveis e salva em arquivo
    \$0 -f json -o estrutura.json         # Salva em formato JSON
    \$0 -f markdown -o README.md          # Salva em formato Markdown
    \$0 -v -s -a                           # Modo verboso, com tamanhos e arquivos ocultos

${BLUE}FORMATOS DISPONÍVEIS:${NC}
    tree     - Formato árvore tradicional (padrão)
    json     - Formato JSON estruturado
    markdown - Formato Markdown para documentação
    plain    - Formato texto simples

${BLUE}ARQUIVO .mapignore:${NC}
    Crie um arquivo .mapignore no diretório para especificar padrões a ignorar.
    Suporta comentários (linhas começadas com #) e padrões glob.

${BLUE}REQUISITOS:${NC}
    - tree (sudo apt install tree)
    - jq (opcional, para formato JSON)
EOF
}

# Função para verificar dependências
verificar_dependencias() {
    local deps_faltando=()
    
    if ! command -v tree &> /dev/null; then
        deps_faltando+=("tree")
    fi
    
    if [ "$FORMATO" = "json" ] && ! command -v jq &> /dev/null; then
        log "ERROR" "jq é necessário para o formato JSON. Instale com 'sudo apt install jq'"
        exit 1
    fi
    
    if [ ${#deps_faltando[@]} -ne 0 ]; then
        log "ERROR" "Dependências faltando: ${deps_faltando[*]}"
        echo -e "${RED}Para instalar no Ubuntu/Debian:${NC}"
        echo "sudo apt install ${deps_faltando[*]}"
        echo -e "${RED}Para instalar no CentOS/RHEL:${NC}"
        echo "sudo yum install ${deps_faltando[*]}"
        echo -e "${RED}Para instalar no macOS:${NC}"
        echo "brew install ${deps_faltando[*]}"
        exit 1
    fi
}

# Função para ler padrões do arquivo .mapignore
ler_mapignore() {
    local arquivo_ignore="$1"
    local padroes=""
    
    if [ ! -f "$arquivo_ignore" ]; then
        log "DEBUG" "Arquivo $arquivo_ignore não encontrado"
        echo "node_modules"
        return
    fi
    
    log "INFO" "Lendo padrões de $arquivo_ignore"
    
    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        line=$(echo "$line" | xargs)
        
        if [ -z "$padroes" ]; then
            padroes="$line"
        else
            padroes="$padroes|$line"
        fi
    done < "$arquivo_ignore"
    
    if [[ "$padroes" != *"node_modules"* ]]; then
        padroes="${padroes:+$padroes|}node_modules"
    fi
    
    echo "$padroes"
}

# Função para gerar saída em formato JSON
gerar_json() {
    local dir="$1"
    local args=("${@:2}")

    log "INFO" "Gerando estrutura em formato JSON"
    tree -J "${args[@]}" "$dir" | jq .
}

# Função para gerar saída em formato Markdown
gerar_markdown() {
    local dir="$1"
    local args=("${@:2}")

    log "INFO" "Gerando estrutura em formato Markdown"

    cat <<EOF
# Estrutura do Projeto

Gerado em: $(date)
Diretório: $dir

\`\`\`
$(tree "${args[@]}" "$dir" 2>/dev/null)
\`\`\`
EOF
}

# Função para gerar saída em formato simples
gerar_plain() {
    local dir="$1"
    local args=("${@:2}")

    log "INFO" "Gerando estrutura em formato texto simples"
    tree "${args[@]}" "$dir"
}

# Função principal de mapeamento
mapear_estrutura() {
    local dir="$1"
    local padroes_ignore="$2"
    
    log "INFO" "Iniciando mapeamento de $dir"
    
    if [ ! -d "$dir" ]; then
        log "ERROR" "Diretório '$dir' não encontrado"
        exit 1
    fi

    local args=()

    # Padrões de ignore
    if [ -n "$padroes_ignore" ]; then
        args+=(-I "$padroes_ignore")
    fi

    # Profundidade
    [ -n "$NIVEL" ] && args+=(-L "$NIVEL")

    # Arquivos ocultos
    [ "$INCLUIR_ARQUIVOS_OCULTOS" = true ] && args+=(-a)

    # Tamanhos
    [ "$MOSTRAR_TAMANHOS" = true ] && args+=(-s)

    # Apenas diretórios
    [ "$APENAS_DIRETORIOS" = true ] && args+=(-d)

    # Cores
    [ "$COLORIR_SAIDA" = false ] && args+=(-n)

    # Permissões
    [ "$INCLUIR_PERMISSOES" = true ] && args+=(-p)

    log "DEBUG" "Opções do tree: ${args[*]}"

    local saida=""
    case "$FORMATO" in
        "json")
            saida=$(gerar_json "$dir" "${args[@]}")
            ;;
        "markdown")
            saida=$(gerar_markdown "$dir" "${args[@]}")
            ;;
        "plain")
            saida=$(gerar_plain "$dir" "${args[@]}")
            ;;
        "tree"|*)
            saida=$(tree "${args[@]}" "$dir")
            ;;
    esac

    if [ $? -ne 0 ]; then
        log "ERROR" "Erro ao gerar estrutura com os argumentos: ${args[*]}"
        exit 1
    fi

    if [ -z "$saida" ]; then
        log "ERROR" "Saída vazia. Nenhum conteúdo foi gerado."
        exit 1
    fi

    if [ -n "$ARQ_SAIDA" ]; then
        echo "$saida" > "$ARQ_SAIDA"
        log "INFO" "Estrutura salva em $ARQ_SAIDA"
    else
        echo "$saida"
    fi
}

# Processa argumentos da linha de comando
while [[ $# -gt 0 ]]; do
    case $1 in
        -l|--level)
            NIVEL="$2"
            shift 2
            ;;
        -o|--output)
            ARQ_SAIDA="$2"
            shift 2
            ;;
        -f|--format)
            FORMATO="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            MOSTRAR_AJUDA=true
            shift
            ;;
        -V|--version)
            MOSTRAR_VERSAO=true
            shift
            ;;
        -a|--all)
            INCLUIR_ARQUIVOS_OCULTOS=true
            shift
            ;;
        -s|--size)
            MOSTRAR_TAMANHOS=true
            shift
            ;;
        -d|--dirs-only)
            APENAS_DIRETORIOS=true
            shift
            ;;
        -C|--no-color)
            COLORIR_SAIDA=false
            shift
            ;;
        -p|--permissions)
            INCLUIR_PERMISSOES=true
            shift
            ;;
        -i|--ignore-file)
            ARQUIVO_MAPIGNORE="$2"
            shift 2
            ;;
        -*)
            log "ERROR" "Opção desconhecida: $1"
            echo "Use -h ou --help para ver as opções disponíveis"
            exit 1
            ;;
        *)
            PROJETO_DIR="$1"
            shift
            ;;
    esac
done

# Verifica se deve mostrar ajuda ou versão
if [ "$MOSTRAR_AJUDA" = true ]; then
    mostrar_ajuda
    exit 0
fi

if [ "$MOSTRAR_VERSAO" = true ]; then
    echo "Mapear Estrutura de Projetos v$VERSAO"
    exit 0
fi

# Valida formato
case "$FORMATO" in
    tree|json|markdown|plain)
        ;;
    *)
        log "ERROR" "Formato inválido: $FORMATO"
        echo "Formatos disponíveis: tree, json, markdown, plain"
        exit 1
        ;;
esac

# Verifica dependências
verificar_dependencias

# Lê padrões do arquivo .mapignore
PADROES_IGNORE=$(ler_mapignore "$ARQUIVO_MAPIGNORE")

log "DEBUG" "Padrões de ignore: $PADROES_IGNORE"

# Executa o mapeamento
mapear_estrutura "$PROJETO_DIR" "$PADROES_IGNORE"

log "INFO" "Mapeamento concluído com sucesso"