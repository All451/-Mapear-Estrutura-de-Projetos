# 🗃️ Mapear Estrutura de Projetos

## 📌 Visão Geral

O script `mapear_estrutura.sh` é uma ferramenta poderosa e flexível para mapear a estrutura de diretórios de projetos. Ele gera uma representação visual em diversos formatos (como árvore, JSON, Markdown e texto simples), permitindo que você documente, compartilhe ou analise a arquitetura de qualquer projeto rapidamente.

---

## 🧰 Requisitos

Antes de executar o script, certifique-se de ter os seguintes pacotes instalados:

- `tree`: Para navegar pela estrutura do diretório
- `jq` (opcional): Para suporte ao formato JSON avançado

### Instalação nos principais sistemas:

#### Ubuntu/Debian:
```bash
sudo apt install tree jq
```

#### CentOS/RHEL:
```bash
sudo yum install tree jq
```

#### macOS (com Homebrew):
```bash
brew install tree jq
```

---

## 🔧 Uso Básico

```bash
./mapear_estrutura.sh [opções] [caminho_do_projeto]
```

Se nenhum caminho for especificado, o script usa o diretório atual (`.`).

---

## ⚙️ Opções Disponíveis

| Opção               | Descrição                                                  |
|---------------------|------------------------------------------------------------|
| `-l NIVEL`<br>`--level NIVEL` | Limita a profundidade da varredura (ex: `-l 2`) |
| `-o ARQUIVO`<br>`--output ARQUIVO` | Salva a saída em um arquivo |
| `-f FORMATO`<br>`--format FORMATO` | Formato de saída (valores: `tree`, `json`, `markdown`, `plain`) |
| `-v`<br>`--verbose` | Ativa modo verboso (mostra logs detalhados) |
| `-h`<br>`--help`    | Mostra ajuda e exemplos                                     |
| `-V`<br>`--version` | Exibe versão do script                                      |
| `-a`<br>`--all`     | Inclui arquivos ocultos (começam com `.`)                  |
| `-s`<br>`--size`    | Mostra tamanho dos arquivos                                |
| `-d`<br>`--dirs-only` | Mostra apenas diretórios                                 |
| `-C`<br>`--no-color` | Desativa uso de cores na saída                            |
| `-p`<br>`--permissions` | Mostra permissões dos arquivos                          |
| `-i ARQ`<br>`--ignore-file ARQ` | Especifica um arquivo `.mapignore` personalizado |

---

## 📄 Formatos de Saída Suportados

### `tree` (padrão)
Saída hierárquica com indentação, similar ao comando `tree`.

```text
.
├── src/
│   ├── main.py
│   └── utils.py
└── README.md
```

### `json`
Estrutura hierárquica em formato JSON válido. Requer `jq` instalado.

```json
{
  "src": {
    "main.py": {},
    "utils.py": {}
  },
  "README.md": {}
}
```

### `markdown`
Formato compatível com documentação Markdown, ideal para integrar em `README.md`.

```markdown
# Estrutura do Projeto

Gerado em: 2025-04-05 14:30:00  
Diretório: /home/user/meu-projeto

```
.
├── src/
│   ├── main.py
│   └── utils.py
└── README.md
```
```

### `plain`
Lista plana de diretórios e arquivos, sem formatação adicional.

```text
src/
src/main.py
src/utils.py
README.md
```

---

## 📁 Arquivo `.mapignore`

Você pode criar um arquivo chamado `.mapignore` na raiz do projeto para ignorar certas pastas ou arquivos durante o mapeamento. O conteúdo segue padrões glob similares ao `.gitignore`.

### Exemplo de `.mapignore`:
```text
# Ignorar estas pastas
node_modules
.git
__pycache__

# Ignorar todos os arquivos temporários
*.tmp
*.swp
```

> A pasta `node_modules` é ignorada por padrão, mesmo que não esteja no `.mapignore`.

---

## 🧪 Exemplos de Uso

### 1. Mapear estrutura básica
```bash
./mapear_estrutura.sh
```

### 2. Mapear até 2 níveis de profundidade e salvar em Markdown
```bash
./mapear_estrutura.sh -l 2 -f markdown -o estrutura.md ~/meu-projeto
```

### 3. Mostrar tamanhos, incluir arquivos ocultos e exibir saída JSON
```bash
./mapear_estrutura.sh -s -a -f json ~/projeto > estrutura.json
```

### 4. Mapear apenas diretórios (ignorando arquivos)
```bash
./mapear_estrutura.sh -d ~/projeto
```

---

## 📦 Informações Adicionais

- **Versão:** 2.1
- **Autor:** Sistema de Mapeamento de Estruturas
- **Licença:** MIT (livre para uso e modificação)

---

## 💡 Dicas

- Use `-v` para depurar problemas durante execução.
- Combine com CI/CD para gerar documentação automaticamente.
- Mantenha o `.mapignore` atualizado para evitar excessos na saída.

---

## 🛠️ Contribuição

Contribuições são bem-vindas! Se você deseja melhorar o script ou esta documentação:

1. Fork o repositório
2. Crie uma nova branch (`git checkout -b feature/nova-feature`)
3. Faça suas alterações
4. Commit suas mudanças (`git commit -m 'Adicionar nova feature'`)
5. Push para sua branch (`git push origin feature/nova-feature`)
6. Abra um Pull Request

