#!/bin/sh
set -eu

outputs=""
for port in 12001 12002 12003 12004 12005 12006 12007 12008 12009 12010 12011; do
  if [ -n "$outputs" ]; then outputs="$outputs|"; fi
  outputs="${outputs}[f=mpegts:onfail=abort]udp://mediamtx:${port}?pkt_size=1316"
done

exec ffmpeg -hide_banner -loglevel warning -re \
  -f lavfi -i "color=c=gray:size=640x360:rate=12,drawbox=x=280:y=140:w=80:h=80:color=white:t=fill:enable=gte(t\\,12)*lt(mod(t-12\\,4)\\,2)" \
  -an -c:v libx264 -preset ultrafast -tune zerolatency \
  -pix_fmt yuv420p -profile:v baseline -g 12 -keyint_min 12 -sc_threshold 0 \
  -map 0:v -f tee "$outputs"
