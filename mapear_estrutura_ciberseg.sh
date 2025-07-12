#!/bin/bash
# script: mapear_estrutura.sh
# Versão: 1.0 (Cibersegurança)
# Uso: ./mapear_estrutura.sh [opções] [caminho_do_projeto]
# Autor: Sistema de Mapeamento de Estruturas (Modo Segurança)

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
VERSAO="3.0"
MODO_SEGURANCA=false

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Função de log
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

# Mostrar ajuda estendida com opções de segurança
mostrar_ajuda() {
    cat << EOF
${GREEN}Mapear Estrutura de Projetos v${VERSAO}${NC} (Modo Segurança)

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
    --security                 Ativa modo de análise de segurança (inclui arquivos sensíveis)

${BLUE}EXEMPLOS:${NC}
    \$0 --security -s -p -a /home/usuario/      # Mapeia com foco em segurança
    \$0 -f json --security /var/www             # Gera JSON com alertas
    \$0 -l 2 -o estrutura.txt ~/projeto         # Mapeia até 2 níveis

${BLUE}FUNCIONALIDADES DE SEGURANÇA:${NC}
    - Detecta arquivos comuns de credenciais (.env, config.php, secrets.yml)
    - Mostra permissões fracas (ex: 777)
    - Identifica logs, histórico bash, chaves SSH, etc.
EOF
}

# Verificar dependências
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

# Ler padrões de ignore
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

# Buscar arquivos sensíveis (senhas, logs, histórico, etc.)
buscar_arquivos_sensiveis() {
    local dir="$1"
    log "INFO" "🔍 Buscando arquivos sensíveis em $dir"

    find "$dir" -type f -name "*.env" -o -name "*.key" -o -name "*.pem" -o -name "*.log" -o -name ".bash_history" -o -name "id_rsa*" -o -name "config.php" -o -name "*.yml" -o -name "*.yaml" 2>/dev/null
}

# Buscar permissões fracas
buscar_permissoes_fracas() {
    local dir="$1"
    log "INFO" "🔒 Buscando permissões fracas em $dir"

    find "$dir" -type f $ -perm -0004 -o -perm -0002 -o -perm -0006 $ -exec ls -l {} \; 2>/dev/null
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
    [ -n "$padroes_ignore" ] && args+=(-I "$padroes_ignore")
    [ -n "$NIVEL" ] && args+=(-L "$NIVEL")
    [ "$INCLUIR_ARQUIVOS_OCULTOS" = true ] && args+=(-a)
    [ "$MOSTRAR_TAMANHOS" = true ] && args+=(-s)
    [ "$APENAS_DIRETORIOS" = true ] && args+=(-d)
    [ "$COLORIR_SAIDA" = false ] && args+=(-n)
    [ "$INCLUIR_PERMISSOES" = true ] && args+=(-p)

    log "DEBUG" "Opções do tree: ${args[*]}"

    local saida=""
    case "$FORMATO" in
        "json")
            saida=$(tree -J "${args[@]}" "$dir" | jq .)
            ;;
        "markdown")
            cat <<EOF
# Estrutura do Diretório

Gerado em: $(date)
Diretório: $dir

\`\`\`
$(tree "${args[@]}" "$dir" 2>/dev/null)
\`\`\`

## 🔍 Arquivos Sensíveis Encontrados
\`\`\`
$(buscar_arquivos_sensiveis "$dir")
\`\`\`

## 🔒 Permissões Fracas Encontradas
\`\`\`
$(buscar_permissoes_fracas "$dir")
\`\`\`
EOF
            ;;
        "plain"|"tree"|*)
            saida=$(tree "${args[@]}" "$dir")
            echo "$saida"
            echo -e "\n🔍 Arquivos Sensíveis:"
            buscar_arquivos_sensiveis "$dir"
            echo -e "\n🔒 Permissões Fracas:"
            buscar_permissoes_fracas "$dir"
            ;;
    esac
}

# Processa argumentos da linha de comando
while [[ $# -gt 0 ]]; do
    case $1 in
        --security)
            MODO_SEGURANCA=true
            INCLUIR_ARQUIVOS_OCULTOS=true
            MOSTRAR_TAMANHOS=true
            INCLUIR_PERMISSOES=true
            shift
            ;;
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

if [ "$MOSTRAR_AJUDA" = true ]; then
    mostrar_ajuda
    exit 0
fi

if [ "$MOSTRAR_VERSAO" = true ]; then
    echo "Mapear Estrutura de Projetos v$VERSAO (Modo Segurança)"
    exit 0
fi

case "$FORMATO" in
    tree|json|markdown|plain)
        ;;
    *)
        log "ERROR" "Formato inválido: $FORMATO"
        echo "Formatos disponíveis: tree, json, markdown, plain"
        exit 1
        ;;
esac

verificar_dependencias
PADROES_IGNORE=$(ler_mapignore "$ARQUIVO_MAPIGNORE")
log "DEBUG" "Padrões de ignore: $PADROES_IGNORE"

if [ -n "$ARQ_SAIDA" ]; then
    mapear_estrutura "$PROJETO_DIR" "$PADROES_IGNORE" > "$ARQ_SAIDA"
    log "INFO" "Estrutura salva em $ARQ_SAIDA"
else
    mapear_estrutura "$PROJETO_DIR" "$PADROES_IGNORE"
fi

log "INFO" "Mapeamento concluído com sucesso"