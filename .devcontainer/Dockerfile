FROM mcr.microsoft.com/devcontainers/dotnet:1-8.0-bookworm

# Args for Claude Code setup
ARG TZ=Asia/Tokyo
ARG CLAUDE_CODE_VERSION=latest
ARG GIT_DELTA_VERSION=0.18.2
ARG ZSH_IN_DOCKER_VERSION=1.2.0

# Install SQL Tools: SQLPackage and sqlcmd
COPY mssql/installSQLtools.sh installSQLtools.sh
RUN bash ./installSQLtools.sh \
     && apt-get clean -y && rm -rf /var/lib/apt/lists/* /tmp/library-scripts

# Install additional development tools
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
        curl \
        wget \
        unzip \
        git \
        jq \
        zsh \
        ripgrep \
        fd-find \
        bat \
        tree \
        nano \
        vim \
        sudo \
        ca-certificates \
        gnupg \
        lsb-release \
    && apt-get clean -y && rm -rf /var/lib/apt/lists/*

# Install git-delta
RUN curl -L "https://github.com/dandavison/delta/releases/download/${GIT_DELTA_VERSION}/git-delta_${GIT_DELTA_VERSION}_amd64.deb" -o /tmp/git-delta.deb \
    && dpkg -i /tmp/git-delta.deb \
    && rm /tmp/git-delta.deb

# Setup Node.js and install Claude Code
RUN su vscode -c "source /usr/local/share/nvm/nvm.sh && nvm install --lts && nvm use --lts && npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" || echo "Claude Code installation failed, continuing..."

# Install and configure zsh (simplified)
RUN su vscode -c "sh -c \"\$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)\" || true"

# Set up Claude Code configuration directory
RUN mkdir -p /home/vscode/.claude \
    && chown -R vscode:vscode /home/vscode/.claude

# Set timezone
ENV TZ=${TZ}
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Add init-firewall script (commented out - requires NET_ADMIN/NET_RAW capabilities)
# COPY init-firewall.sh /usr/local/bin/init-firewall.sh
# RUN chmod +x /usr/local/bin/init-firewall.sh

# Environment variables for Claude Code
ENV CLAUDE_CONFIG_DIR=/home/vscode/.claude
ENV NODE_OPTIONS=--max-old-space-size=4096
