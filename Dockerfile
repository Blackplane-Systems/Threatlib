FROM python:3.11-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml README.md LICENSE ./
COPY threatlib ./threatlib
COPY threatlib.yaml ./threatlib.yaml
COPY examples ./examples

RUN pip install --no-cache-dir -e .

EXPOSE 8000
CMD ["threatlib-server", "--config", "threatlib.yaml", "--host", "0.0.0.0", "--port", "8000"]
