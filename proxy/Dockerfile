FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

COPY pyproject.toml .
# Install dependencies into a venv managed by uv.
# --no-install-project: we're a script, not a package — just install the deps.
RUN uv sync --no-install-project

COPY tls_parser.py ja4.py classifier.py lookup.py proxy.py ./

CMD ["uv", "run", "python", "-u", "proxy.py"]
