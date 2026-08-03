FROM python:3.12.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY src/authz_service/requirements.txt .
RUN pip install --no-cache-dir --timeout 120 --retries 5 --requirement requirements.txt \
    && addgroup --system authz \
    && adduser --system --ingroup authz authz

COPY --chown=authz:authz src/authz_service ./authz_service

USER authz

EXPOSE 8001

CMD ["uvicorn", "authz_service.main:app", "--host", "0.0.0.0", "--port", "8001"]
