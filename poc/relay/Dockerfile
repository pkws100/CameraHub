FROM alpine:3.22

RUN apk add --no-cache vlc \
    && addgroup -S relay \
    && adduser -S -G relay relay

COPY entrypoint.sh /usr/local/bin/zmodo-vlc-relay
RUN chmod 0755 /usr/local/bin/zmodo-vlc-relay

USER relay
ENTRYPOINT ["/usr/local/bin/zmodo-vlc-relay"]
