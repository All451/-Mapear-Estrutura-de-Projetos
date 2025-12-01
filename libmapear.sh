#!/bin/bash
# Biblioteca de funções para mapeamento de estrutura de diretórios
# Nome: libmapear.sh
# Versão: 1.0
# Descrição: Biblioteca de utilitários para mapeamento de estrutura de diretórios

# Função para verificar se uma função existe
funcao_existe() {
    declare -f "$1" > /dev/null
}

# Função para logging
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")
            [ "$VERBOSE" = true ] && echo -e "\033[0;32m[INFO]\033[0m $timestamp - $message" >&2
            ;;
        "WARN")
            echo -e "\033[1;33m[WARN]\033[0m $timestamp - $message" >&2
            ;;
        "ERROR")
            echo -e "\033[0;31m[ERROR]\033[0m $timestamp - $message" >&2
            ;;
        "DEBUG")
            [ "$VERBOSE" = true ] && echo -e "\033[0;34m[DEBUG]\033[0m $timestamp - $message" >&2
            ;;
    esac
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
        echo -e "\033[0;31mPara instalar no Ubuntu/Debian:\033[0m"
        echo "sudo apt install ${deps_faltando[*]}"
        echo -e "\033[0;31mPara instalar no CentOS/RHEL:\033[0m"
        echo "sudo yum install ${deps_faltando[*]}"
        echo -e "\033[0;31mPara instalar no macOS:\033[0m"
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

# Função para buscar arquivos sensíveis (modo segurança)
buscar_arquivos_sensiveis() {
    local dir="$1"
    log "INFO" "🔍 Buscando arquivos sensíveis em $dir"

    find "$dir" -type f \( -name "*.env" -o -name "*.key" -o -name "*.pem" -o -name "*.log" -o -name ".bash_history" -o -name "id_rsa*" -o -name "config.php" -o -name "*.yml" -o -name "*.yaml" -o -name "*.json" -o -name "secrets*" -o -name "*.secret" -o -name "passwd" -o -name "shadow" -o -name "htpasswd" \) 2>/dev/null
}

# Função para buscar permissões fracas
buscar_permissoes_fracas() {
    local dir="$1"
    log "INFO" "🔒 Buscando permissões fracas em $dir"

    find "$dir" -type f \( -perm -0004 -o -perm -0002 -o -perm -0006 \) -exec ls -l {} \; 2>/dev/null
}

# Função principal de mapeamento
mapear_estrutura() {
    local dir="$1"
    local padroes_ignore="$2"
    local modo_seguranca="${3:-false}"
    
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
            if [ "$modo_seguranca" = true ]; then
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
            else
                saida=$(gerar_markdown "$dir" "${args[@]}")
            fi
            ;;
        "plain")
            saida=$(gerar_plain "$dir" "${args[@]}")
            if [ "$modo_seguranca" = true ]; then
                echo "$saida"
                echo -e "\n🔍 Arquivos Sensíveis:"
                buscar_arquivos_sensiveis "$dir"
                echo -e "\n🔒 Permissões Fracas:"
                buscar_permissoes_fracas "$dir"
                return
            fi
            ;;
        "tree"|*)
            saida=$(tree "${args[@]}" "$dir" 2>/dev/null)
            if [ "$modo_seguranca" = true ]; then
                echo "$saida"
                echo -e "\n🔍 Arquivos Sensíveis:"
                buscar_arquivos_sensiveis "$dir"
                echo -e "\n🔒 Permissões Fracas:"
                buscar_permissoes_fracas "$dir"
                return
            fi
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

# Exportar funções para uso externo
export -f log
export -f verificar_dependencias
export -f ler_mapignore
export -f gerar_json
export -f gerar_markdown
export -f gerar_plain
export -f buscar_arquivos_sensiveis
export -f buscar_permissoes_fracas
export -f mapear_estrutura