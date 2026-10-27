FROM node:24.21.0-bookworm-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /requirements.txt
RUN python3 -m venv /opt/oidf && /opt/oidf/bin/pip install --no-cache-dir --timeout 120 --retries 5 -r /requirements.txt
ENV PATH="/opt/oidf/bin:${PATH}"
WORKDIR /work
