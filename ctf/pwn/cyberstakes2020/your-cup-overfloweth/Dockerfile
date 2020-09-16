FROM ubuntu:18.04

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y \
    socat \
&& rm -rf /var/lib/apt/lists/*

RUN useradd -m cup

WORKDIR /home/cup

COPY cup .
COPY flag.txt .
RUN chown -R root:cup /home/cup && \
    chmod -R 750 /home/cup && \
    chmod 740 /home/cup/flag.txt

EXPOSE 55284
USER cup
CMD while true; do \
        socat TCP-LISTEN:55284,reuseaddr,fork EXEC:"./cup",stderr; \
    done
