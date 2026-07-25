FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apk add --no-cache ffmpeg patch \
    && addgroup -S bridge \
    && adduser -S -G bridge bridge
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY pycloudedge-czeview.patch /tmp/pycloudedge-czeview.patch
RUN package_root="$(python -c 'import site; print(site.getsitepackages()[0])')" \
    && patch -d "$package_root" -p1 < /tmp/pycloudedge-czeview.patch \
    && python -c "import inspect; from cloudedge import CloudEdgeClient; assert 'source_app' in inspect.signature(CloudEdgeClient).parameters" \
    && rm /tmp/pycloudedge-czeview.patch
COPY bridge.py /app/bridge.py
COPY tests /app/tests
RUN mkdir -p /data /run/bridge-health \
    && chown -R bridge:bridge /data /run/bridge-health
USER bridge
ENTRYPOINT ["python", "/app/bridge.py"]
