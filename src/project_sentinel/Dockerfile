FROM python:3.12.8-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY src/project_sentinel/requirements.txt /tmp/project-sentinel-requirements.txt
RUN python -m pip install --no-cache-dir --requirement /tmp/project-sentinel-requirements.txt \
    && addgroup --system sentinel \
    && adduser --system --ingroup sentinel --home /nonexistent sentinel

COPY pyproject.toml README.md ./
COPY src ./src
COPY scripts ./scripts
COPY data ./data
COPY schemas ./schemas
COPY config/safe-api-tool ./config/safe-api-tool

RUN python -m pip install --no-cache-dir --no-deps --editable . \
    && mkdir -p /app/security-results/runs/week-6 \
    && chown -R sentinel:sentinel /app/security-results

USER sentinel

ENTRYPOINT ["python", "-m", "project_sentinel"]
CMD ["demo", "--provider", "deterministic", "--output-root", "/app/security-results/runs/week-6"]
