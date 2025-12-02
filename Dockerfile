# Use uma imagem base segura e atualizada
FROM python:3.11-slim

# Metadados da imagem
LABEL maintainer="Cybersecurity Toolkit Team"
LABEL description="A comprehensive cybersecurity toolkit for system analysis, network security, firewall management, and threat detection"
LABEL version="3.0.0"

# Definir variáveis de ambiente
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1

# Atualizar sistema e instalar dependências do sistema
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    tree \
    ufw \
    net-tools \
    iproute2 \
    ca-certificates \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Instalar Docker CLI se necessário
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update && apt-get install -y docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Criar diretório de trabalho
WORKDIR /app

# Copiar arquivos de dependências
COPY requirements.txt .

# Instalar dependências Python
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copiar código da aplicação
COPY . .

# Criar usuário não-root para execução
RUN useradd --create-home --shell /bin/bash --uid 1000 cybersec && \
    usermod -aG docker cybersec && \
    chown -R cybersec:cybersec /app

# Alternar para o usuário não-root
USER cybersec

# Expor portas necessárias para funcionalidades do toolkit (se necessário)
EXPOSE 80 443

# Comando padrão
CMD ["python", "cybersec_toolkit.py", "--help"]