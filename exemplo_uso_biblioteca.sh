#!/bin/bash
# Exemplo de uso da biblioteca libmapear.sh
# Demonstração de como reutilizar as funções em outros scripts

# Importar a biblioteca
source "./libmapear.sh" 2>/dev/null || {
    echo "ERRO: Não foi possível encontrar libmapear.sh"
    echo "Certifique-se de que o arquivo está no mesmo diretório deste script."
    exit 1
}

echo "=== Exemplo de uso da biblioteca libmapear.sh ==="
echo

# Exemplo 1: Usar a função de logging
log "INFO" "Iniciando exemplo de uso da biblioteca"

# Exemplo 2: Ler padrões de ignore
echo "Lendo padrões de ignore do .mapignore local:"
PADROES_IGNORE=$(ler_mapignore ".mapignore")
echo "Padrões: $PADROES_IGNORE"
echo

# Exemplo 3: Mapear estrutura atual em modo simples
echo "Mapeando estrutura do diretório atual:"
mapear_estrutura "." "$PADROES_IGNORE" "false"
echo

# Exemplo 4: Mapear com modo segurança (se estiver em um diretório seguro para testes)
echo "Executando varredura de segurança no diretório atual:"
buscar_arquivos_sensiveis "."
echo

echo "=== Fim do exemplo ==="