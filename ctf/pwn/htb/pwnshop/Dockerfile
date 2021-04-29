FROM ubuntu

RUN apt-get update --yes && apt-get install --yes \
    socat

RUN useradd --create-home pwnshop

WORKDIR /home/pwnshop
COPY pwnshop .
COPY flag.txt .
RUN chown --recursive root:pwnshop /home/pwnshop && \
    chmod --recursive 750 /home/pwnshop && \
    chmod 740 /home/pwnshop/flag.txt

EXPOSE 4444
USER pwnshop
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./pwnshop",stderr; \
    done
