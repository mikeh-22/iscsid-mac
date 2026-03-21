FROM ubuntu:24.04

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        tgt \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

# 128 MiB backing disk image
RUN dd if=/dev/zero of=/disk0.img bs=1M count=128 status=none

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3260

ENTRYPOINT ["/entrypoint.sh"]
