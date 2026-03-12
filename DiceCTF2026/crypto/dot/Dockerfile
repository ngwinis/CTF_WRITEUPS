FROM python:3.14-slim-bookworm AS chroot

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgmp-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --br --no-cache fastecdsa tqdm
COPY add.py circuit.py dpp.py flag.txt server.py snarg.py vk.bin ./

RUN mv server.py run && \
    chmod 755 /app/run

FROM pwn.red/jail
COPY --from=chroot / /srv
ENV JAIL_MEM=256M JAIL_CPU=500 JAIL_TIME=600
