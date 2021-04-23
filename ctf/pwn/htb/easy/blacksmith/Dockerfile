FROM ubuntu

RUN apt-get update --yes && apt-get install --yes \
    socat

RUN useradd --create-home blacksmith

WORKDIR /home/blacksmith
COPY blacksmith .
COPY flag.txt .
RUN chown --recursive root:blacksmith /home/blacksmith && \
    chmod --recursive 750 /home/blacksmith && \
    chmod 740 /home/blacksmith/flag.txt

EXPOSE 4444
USER blacksmith
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./blacksmith",stderr; \
    done
