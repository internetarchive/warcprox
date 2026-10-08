FROM ghcr.io/astral-sh/uv:python3.12-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends openssh-server rsync \
    && mkdir -p /run/sshd \
    && echo 'AuthorizedKeysFile /keys/authorized_keys' >> /etc/ssh/sshd_config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN uv sync --frozen --no-dev
RUN uv pip install --index-url https://nexus.us.archive.org/repository/pypi-group/simple trough-client

# spin up ssh in order to start warcprox after
ENTRYPOINT ["sh", "-c", "/usr/sbin/sshd && exec \"$@\"", "sh"]
