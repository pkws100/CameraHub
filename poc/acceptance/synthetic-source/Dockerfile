FROM alpine:3.22
RUN apk add --no-cache ffmpeg
COPY start.sh /start.sh
RUN chmod 0755 /start.sh
ENTRYPOINT ["/start.sh"]
