FROM bluenviron/mediamtx:1.19.2 AS mediamtx

FROM alpine:3.22
RUN apk add --no-cache wget
COPY --from=mediamtx /mediamtx /mediamtx
ENTRYPOINT ["/mediamtx"]
