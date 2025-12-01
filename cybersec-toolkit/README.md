# Cybersecurity Toolkit

## Descrição
O Cybersecurity Toolkit é um conjunto abrangente de ferramentas de segurança cibernética para sistemas Linux, projetado para auditoria de segurança, monitoramento de rede, gerenciamento de firewall e verificação de segurança de containers Docker.

## Recursos
- **Varredura de Sistema**: Verificação de permissões, arquivos suspeitos e configurações inseguras
- **Análise de Rede**: Detecção de portas abertas, serviços expostos e vulnerabilidades de rede
- **Gerenciamento de Firewall**: Sistema de banimento de IPs com UFW e iptables
- **Segurança Docker**: Verificação de configurações de segurança de containers
- **Relatórios Profissionais**: Geração de relatórios em múltiplos formatos (Markdown, JSON, HTML, TXT)

## Instalação

### Pré-requisitos
- Python 3.8+
- Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+)
- Permissões de sudo para operações de firewall
- UFW (Uncomplicated Firewall) instalado
- Docker (opcional, para verificação de containers)

### Instalação
```bash
git clone https://github.com/example/cybersec-toolkit.git
cd cybersec-toolkit
pip install -r requirements.txt
python setup.py install
```

## Uso

### Comandos Básicos
```bash
# Mostrar versão
cybersec --version

# Mostrar ajuda
cybersec --help

# Varredura completa
cybersec scan --full

# Verificar status do firewall
cybersec firewall status

# Analisar rede
cybersec network analyze

# Escanear containers Docker
cybersec docker scan
```

### Comandos de Varredura
```bash
# Varredura rápida
cybersec scan --quick

# Apenas sistema
cybersec scan --system

# Apenas rede
cybersec scan --network

# Apenas sistema de arquivos
cybersec scan --filesystem [PATH]

# Apenas Docker
cybersec scan --docker
```

### Comandos de Firewall
```bash
# Banir IP
cybersec firewall ban 192.168.1.100 --reason "Ataque suspeito"

# Desbanir IP
cybersec firewall unban 192.168.1.100

# Listar IPs banidos
cybersec firewall list

# Verificar status de IP
cybersec firewall check 192.168.1.100
```

### Comandos de Rede
```bash
# Listar portas abertas
cybersec network ports

# Verificar porta específica
cybersec network check 80

# Análise completa de rede
cybersec network analyze
```

### Comandos Docker
```bash
# Escanear containers
cybersec docker scan

# Relatório detalhado
cybersec docker report

# Verificar container específico
cybersec docker check <CONTAINER_ID>
```

### Comandos de Configuração
```bash
# Mostrar configuração
cybersec config show

# Definir valor
cybersec config set log_level DEBUG

# Resetar para padrão
cybersec config reset
```

### Comandos de Relatório
```bash
# Gerar relatório (padrão: markdown)
cybersec report generate

# Gerar relatório em JSON
cybersec report generate --format json

# Histórico de scans
cybersec report history

# Exportar último relatório
cybersec report export /path/to/report.md
```

## Configuração

O toolkit usa um arquivo de configuração YAML localizado em `~/.cybersec/config.yaml` ou `/etc/cybersec/config.yaml`. Veja `config/cybersec.yaml.example` para um exemplo completo.

## Contribuição

1. Faça fork do projeto
2. Crie um branch para sua feature (`git checkout -b feature/nova-feature`)
3. Commit suas mudanças (`git commit -m 'Adiciona nova feature'`)
4. Push para o branch (`git push origin feature/nova-feature`)
5. Abra um Pull Request

## Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## Autor

Security Team