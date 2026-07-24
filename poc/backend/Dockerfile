FROM python:3.14-alpine

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apk add --no-cache ffmpeg su-exec \
    && addgroup -S app \
    && adduser -S -G app app
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY . /app
RUN chmod 0755 /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
