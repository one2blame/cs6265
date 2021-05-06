FROM ubuntu:xenial

RUN apt-get update --yes && apt-get install --yes \
    socat

RUN useradd --create-home ropme

WORKDIR /home/ropme
COPY ropme .
COPY flag.txt .
RUN chown --recursive root:ropme /home/ropme && \
    chmod --recursive 750 /home/ropme && \
    chmod 740 /home/ropme/flag.txt

EXPOSE 4444
USER ropme
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./ropme",stderr; \
    done
