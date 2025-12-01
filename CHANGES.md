# Changelog

Todas as mudanças notáveis neste projeto estão documentadas neste arquivo.

## [3.0.0] - 2025-12-01

### Adicionado
- Criada biblioteca modular `libmapear.sh` com funções reutilizáveis
- Adicionado modo de segurança (`--security`) que detecta arquivos sensíveis e permissões fracas
- Adicionado suporte para exportar em múltiplos formatos (tree, JSON, Markdown, plain)
- Criado Makefile para facilitar instalação e uso
- Adicionado arquivo package.json para compatibilidade com npm
- Criado exemplo de uso da biblioteca em outros scripts
- Adicionado sistema de logging profissional com níveis (INFO, WARN, ERROR, DEBUG)
- Adicionado suporte para arquivos .mapignore personalizados
- Implementado sistema de tratamento de erros robusto

### Alterado
- Refatorado código para seguir padrões profissionais de modularidade
- Consolidados os dois scripts anteriores em uma solução unificada e modular
- Atualizado README com documentação completa da biblioteca profissional
- Melhorada a estrutura de argumentos e opções de linha de comando
- Corrigido inconsistências de versão entre diferentes arquivos

### Melhorado
- Performance e eficiência do código
- Segurança com detecção de arquivos sensíveis e permissões fracas
- Modularidade para permitir reutilização em outros projetos
- Documentação completa e exemplos de uso
- Sistema de build e testes automatizados

### Removido
- Código duplicado entre os scripts anteriores
- Funções redundantes e ineficientes

## [2.2.0] - Versão anterior (antes da refatoração)

### Notas
- Versão funcional mas com código duplicado e estrutura não modular
- Implementações paralelas nos scripts `mapear_estrutura.sh` e `mapear_estrutura_ciberseg.sh`

## [1.0.0] - Versão inicial

### Notas
- Primeira versão funcional do script de mapeamento de estrutura
- Funcionalidades básicas de mapeamento de diretórios