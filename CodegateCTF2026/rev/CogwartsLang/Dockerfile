FROM debian:bookworm-slim@sha256:98f4b71de414932439ac6ac690d7060df1f27161073c5036a7553723881bffbe

ENV PORT=20266

RUN apt-get update \
  && apt-get install -y --no-install-recommends socat ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN useradd -m cogwarts
WORKDIR /home/cogwarts

COPY deploy/grimc /home/cogwarts/bin/
COPY deploy/grimrun /home/cogwarts/bin/
COPY deploy/harness /home/cogwarts/bin/
COPY deploy/liboracle_host.so /home/cogwarts/bin/
COPY deploy/libstdlib_host.so /home/cogwarts/bin/
COPY deploy/run.sh /home/cogwarts/run.sh

RUN chmod +x /home/cogwarts/bin/* /home/cogwarts/run.sh \
  && chown -R cogwarts:cogwarts /home/cogwarts

USER cogwarts
EXPOSE ${PORT}
CMD ["sh", "-c", "exec socat TCP-LISTEN:${PORT},reuseaddr,fork EXEC:/home/cogwarts/run.sh,stderr"]
