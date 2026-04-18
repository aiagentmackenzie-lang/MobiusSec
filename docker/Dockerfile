FROM python:3.12-slim

LABEL maintainer="MobiusSec"
LABEL description="MobiusSec — Unified Mobile Security Platform"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    wget \
    unzip \
    yara \
    strings \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install apktool
RUN wget -q https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar -O /opt/apktool.jar \
    && echo '#!/bin/bash\njava -jar /opt/apktool.jar "$@"' > /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool

# Install jadx
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip -O /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && ln -s /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui \
    && rm /tmp/jadx.zip

WORKDIR /app

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy source code
COPY core/ ./core/
COPY rules/ ./rules/
COPY tests/ ./tests/

# Install in editable mode
RUN pip install --no-cache-dir -e .

ENTRYPOINT ["mobius"]
CMD ["--help"]