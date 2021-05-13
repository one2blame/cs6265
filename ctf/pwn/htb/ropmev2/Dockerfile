FROM ubuntu:xenial

RUN apt-get update --yes && apt-get install --yes \
    socat

RUN useradd --create-home ropmev2

WORKDIR /home/ropmev2
COPY ropmev2 .
COPY flag.txt .
RUN chown --recursive root:ropmev2 /home/ropme && \
    chmod --recursive 750 /home/ropmev2 && \
    chmod 740 /home/ropmev2/flag.txt

EXPOSE 4444
USER ropmev2
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./ropmev2",stderr; \
    done
