# Padrões de Codificação - Cybersecurity Toolkit

## Sumário
1. [Introdução](#introdução)
2. [Estrutura de Projetos](#estrutura-de-projetos)
3. [Padrões de Codificação Python](#padrões-de-codificação-python)
4. [Segurança no Código](#segurança-no-código)
5. [Testes e Qualidade de Código](#testes-e-qualidade-de-código)
6. [Documentação](#documentação)
7. [Controle de Versão](#controle-de-versão)

## Introdução

Este documento estabelece os padrões e práticas recomendadas para o desenvolvimento do Cybersecurity Toolkit. O objetivo é garantir consistência, segurança e manutenibilidade do código.

## Estrutura de Projetos

### Diretórios
```
cybersec-toolkit/
├── cybersec/                 # Módulos principais
│   ├── __init__.py
│   ├── cli/                  # Componentes de interface de linha de comando
│   ├── core/                 # Componentes centrais
│   └── utils/                # Utilitários
├── tests/                    # Testes unitários e de integração
├── docs/                     # Documentação
├── scripts/                  # Scripts auxiliares
├── config/                   # Arquivos de configuração
├── requirements.txt          # Dependências Python
├── pyproject.toml            # Configurações de build e ferramentas
├── Dockerfile                # Containerização
├── docker-compose.yml        # Orquestração de containers
├── Makefile                  # Tarefas de desenvolvimento
└── README.md                 # Documentação principal
```

### Nomenclatura de Arquivos
- Usar `snake_case` para arquivos Python: `security_scanner.py`
- Usar `PascalCase` para classes: `class SecurityScanner:`
- Usar `snake_case` para funções e variáveis: `def scan_ports():`

## Padrões de Codificação Python

### Formatação
- Seguir [PEP 8](https://peps.python.org/pep-0008/)
- Usar Black para formatação automática
- Limite de linha: 88 caracteres
- Usar aspas duplas para strings

### Tipagem
- Usar tipagem de tipo para todas as funções públicas
- Utilizar `typing` para estruturas complexas

```python
from typing import Dict, List, Optional, Union

def scan_ports(target: str, ports: List[int], timeout: float = 5.0) -> Dict[str, Union[List, str]]:
    """Exemplo de função com tipagem."""
    pass
```

### Docstrings
- Usar docstrings em todas as funções públicas
- Seguir formato Google ou Sphinx

```python
def check_port_security(port_number: int) -> Dict[str, Union[str, int]]:
    """Verifica o status de segurança de uma porta específica.
    
    Args:
        port_number: Número da porta a ser verificada (1-65535)
        
    Returns:
        Dicionário com informações de segurança da porta
        
    Raises:
        ValueError: Se o número da porta estiver fora do intervalo válido
    """
    pass
```

## Segurança no Código

### Validação de Entrada
- Sempre validar e sanitizar entradas do usuário
- Usar `pathlib.Path` para operações de sistema de arquivos
- Implementar verificação de permissões

```python
from pathlib import Path

def safe_file_operation(filepath: str) -> str:
    """Operação segura de arquivo com proteção contra directory traversal."""
    # Sanitize path
    safe_path = Path(filepath).resolve()
    
    # Verify path is within allowed directory
    try:
        safe_path.relative_to(Path.cwd())
    except ValueError:
        raise ValueError(f"Path traversal detected: {filepath}")
    
    # Continue com operação segura
    with open(safe_path, 'r') as f:
        return f.read()
```

### Execução de Comandos
- Usar `subprocess.run` com `shell=False`
- Validar comandos antes de executar
- Implementar timeouts

### Permissões e Controle de Acesso
- Implementar verificação de permissões
- Evitar operações com privilégios desnecessários
- Usar mecanismos de logging adequados

## Testes e Qualidade de Código

### Tipos de Testes
- **Testes Unitários**: Testar funções individuais
- **Testes de Integração**: Testar interações entre módulos
- **Testes de Segurança**: Testar vulnerabilidades conhecidas

### Frameworks
- Pytest para testes
- Coverage para análise de cobertura
- Bandit para análise de segurança estática

### Exemplo de Teste
```python
import pytest
from cybersec.core.network import check_port_security

def test_check_port_security_valid_input():
    """Testa a função check_port_security com entrada válida."""
    result = check_port_security(80)
    assert isinstance(result, dict)
    assert 'port' in result
    assert result['port'] == 80

def test_check_port_security_invalid_input():
    """Testa a função check_port_security com entrada inválida."""
    with pytest.raises(ValueError):
        check_port_security(99999)  # Porta fora do intervalo
```

## Documentação

### Docstrings
- Documentar todas as funções públicas
- Incluir exemplos de uso quando apropriado
- Documentar exceções lançadas

### README
- Descrição clara do propósito do projeto
- Instruções de instalação e uso
- Exemplos de uso
- Informações de contribuição

### CHANGELOG
- Manter CHANGELOG atualizado com todas as versões
- Seguir formato [Keep a Changelog](https://keepachangelog.com/)

## Controle de Versão

### Commits
- Mensagens de commit claras e descritivas
- Seguir convenção [Conventional Commits](https://www.conventionalcommits.org/)
- Exemplo: `feat(network): add port scanning functionality`

### Branches
- `main`: Código estável e testado
- `develop`: Código em desenvolvimento
- `feature/*`: Novas funcionalidades
- `hotfix/*`: Correções críticas

### Pull Requests
- Título descritivo
- Descrição detalhada das mudanças
- Referência a issues quando aplicável
- Revisão por pares obrigatória