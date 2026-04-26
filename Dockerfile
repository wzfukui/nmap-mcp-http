# Nmap MCP Server Docker Image

ARG PYTHON_IMAGE=python:3.11-slim
FROM ${PYTHON_IMAGE}

ARG VERSION=dev
ARG USE_CHINA_MIRRORS=false

LABEL org.opencontainers.image.title="nmap-mcp-http"
LABEL org.opencontainers.image.description="Nmap MCP Server over Streamable HTTP"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.source="https://github.com/wzfukui/nmap-mcp-http"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=Asia/Shanghai

WORKDIR /app

# Optional China mainland mirrors for local builds:
# docker build --build-arg USE_CHINA_MIRRORS=true .
RUN if [ "$USE_CHINA_MIRRORS" = "true" ]; then \
        sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources \
        && sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources; \
    fi

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN if [ "$USE_CHINA_MIRRORS" = "true" ]; then \
        pip install --no-cache-dir -r requirements.txt \
            -i https://mirrors.aliyun.com/pypi/simple/ \
            --trusted-host mirrors.aliyun.com; \
    else \
        pip install --no-cache-dir -r requirements.txt; \
    fi

COPY . .

EXPOSE 3004

ENTRYPOINT []

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import socket; s=socket.create_connection(('127.0.0.1', 3004), 2); s.close()" || exit 1

CMD ["python", "server.py"]
