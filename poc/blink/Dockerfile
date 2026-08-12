FROM python:3.14-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates ffmpeg \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 blink \
    && useradd --system --uid 10001 --gid blink --home-dir /nonexistent --shell /usr/sbin/nologin blink

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /app/requirements.txt
COPY bridge.py /app/bridge.py
COPY tests /app/tests

USER 10001:10001
EXPOSE 8788
ENTRYPOINT ["python", "/app/bridge.py"]
