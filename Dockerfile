FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY llm_guard_lab ./llm_guard_lab
COPY THIRD_PARTY_NOTICES.md ./
COPY THIRD_PARTY_LICENSES ./THIRD_PARTY_LICENSES/

RUN pip install --no-cache-dir .

ENV LLGL_DB_PATH=/app/data/llm-guard-lab.db
RUN mkdir -p /app/data
VOLUME /app/data

EXPOSE 8505

CMD ["llm-guard-lab", "serve", "--host", "0.0.0.0", "--port", "8505"]
