# Makefile para a biblioteca libmapear.sh
# Facilita a instalação e uso da biblioteca

SHELL := /bin/bash
SCRIPTS = mapear_estrutura.sh libmapear.sh
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

.PHONY: all install uninstall test help

all: help

install:
	@echo "Instalando scripts no sistema..."
	@for script in $(SCRIPTS); do \
		if [ -f "$$script" ]; then \
			install -m 755 "$$script" "$(BINDIR)/$$script"; \
			echo "Instalado: $(BINDIR)/$$script"; \
		else \
			echo "Arquivo não encontrado: $$script"; \
		fi \
	done
	@echo "Instalação concluída!"

uninstall:
	@echo "Removendo scripts do sistema..."
	@for script in $(SCRIPTS); do \
		if [ -f "$(BINDIR)/$$script" ]; then \
			rm -f "$(BINDIR)/$$script"; \
			echo "Removido: $(BINDIR)/$$script"; \
		fi \
	done
	@echo "Remoção concluída!"

test:
	@echo "Executando testes básicos..."
	@echo "1. Testando help..."
	@./mapear_estrutura.sh --help > /dev/null
	@echo "✓ Help funcionando"
	@echo "2. Testando mapeamento básico..."
	@./mapear_estrutura.sh -f plain . 2>/dev/null | head -n 5
	@echo "✓ Mapeamento básico funcionando"
	@echo "3. Testando modo segurança..."
	@./mapear_estrutura.sh --security -f plain . 2>/dev/null | head -n 5
	@echo "✓ Modo segurança funcionando"
	@echo "Todos os testes básicos passaram!"

example:
	@echo "Executando exemplo de uso da biblioteca..."
	@./exemplo_uso_biblioteca.sh

help:
	@echo "Makefile para a biblioteca libmapear.sh"
	@echo ""
	@echo "Comandos disponíveis:"
	@echo "  install    - Instala os scripts no sistema"
	@echo "  uninstall  - Remove os scripts do sistema"
	@echo "  test       - Executa testes básicos"
	@echo "  example    - Executa exemplo de uso da biblioteca"
	@echo "  help       - Mostra esta ajuda"
	@echo ""
	@echo "Variáveis configuráveis:"
	@echo "  PREFIX     - Prefixo de instalação (padrão: /usr/local)"
	@echo "  BINDIR     - Diretório de instalação (padrão: PREFIX/bin)"
	@echo ""