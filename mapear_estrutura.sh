#!/bin/bash
# script: mapear_estrutura.sh
# Versão: 3.0
# Uso: ./mapear_estrutura.sh [opções] [caminho_do_projeto]
# Autor: Sistema de Mapeamento de Estruturas
# Descrição: Ferramenta para mapeamento de estrutura de diretórios com funcionalidades de segurança

set -euo pipefail

# Importar biblioteca
source "$(dirname "$0")/libmapear.sh" 2>/dev/null || {
    echo "ERRO: Não foi possível encontrar libmapear.sh"
    echo "Certifique-se de que o arquivo está no mesmo diretório deste script."
    exit 1
}

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

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
    --security                 Ativa modo de análise de segurança (busca arquivos sensíveis e permissões fracas)

${BLUE}EXEMPLOS:${NC}
    \$0                                    # Mapeia diretório atual
    \$0 /caminho/projeto                   # Mapeia projeto específico
    \$0 -l 3 -o estrutura.txt ~/projeto   # Mapeia até 3 níveis e salva em arquivo
    \$0 -f json -o estrutura.json         # Salva em formato JSON
    \$0 -f markdown -o README.md          # Salva em formato Markdown
    \$0 -v -s -a                           # Modo verboso, com tamanhos e arquivos ocultos
    \$0 --security -s -p -a /home/usuario # Modo segurança com mais detalhes

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
log "DEBUG" "Modo segurança: $MODO_SEGURANCA"

# Executa o mapeamento
mapear_estrutura "$PROJETO_DIR" "$PADROES_IGNORE" "$MODO_SEGURANCA"

log "INFO" "Mapeamento concluído com sucesso"