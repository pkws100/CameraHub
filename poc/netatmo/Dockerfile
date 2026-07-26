FROM python:3.14-alpine

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apk add --no-cache ffmpeg \
    && addgroup -S bridge \
    && adduser -S -G bridge bridge
WORKDIR /app
COPY bridge.py /app/bridge.py
RUN mkdir -p /run/bridge-health && chown -R bridge:bridge /run/bridge-health
USER bridge
ENTRYPOINT ["python", "/app/bridge.py"]
