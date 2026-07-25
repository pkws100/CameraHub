FROM alpine:3.22

RUN apk add --no-cache ffmpeg python3 vlc \
    && addgroup -S manager \
    && adduser -S -G manager manager
WORKDIR /app
COPY manager.py /app/manager.py
RUN mkdir -p /run/relay-secrets /run/relay-health \
    && chown -R manager:manager /run/relay-secrets /run/relay-health
USER manager
ENTRYPOINT ["python3", "/app/manager.py"]
