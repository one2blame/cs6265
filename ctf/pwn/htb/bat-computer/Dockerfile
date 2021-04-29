FROM ubuntu

RUN apt-get update --yes && apt-get install --yes \
    socat

RUN useradd --create-home batcomputer

WORKDIR /home/batcomputer
COPY batcomputer .
COPY flag.txt .
RUN chown --recursive root:batcomputer /home/batcomputer && \
    chmod --recursive 750 /home/batcomputer && \
    chmod 740 /home/batcomputer/flag.txt

EXPOSE 4444
USER batcomputer
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./batcomputer",stderr; \
    done
