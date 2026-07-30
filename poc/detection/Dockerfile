FROM python:3.14-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system detector \
    && useradd --system --gid detector --home-dir /app --no-create-home detector
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: --requirement /app/requirements.txt
COPY detector.py worker.py /app/
COPY tests /app/tests
RUN mkdir -p /run/detection-health \
    && chown detector:detector /run/detection-health
USER detector
ENTRYPOINT ["python", "/app/worker.py"]
