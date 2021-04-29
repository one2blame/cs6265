FROM ubuntu

RUN apt-get update --yes && apt-get install --yes \
    socat

RUN useradd --create-home htb-console

WORKDIR /home/htb-console
COPY htb-console .
COPY flag.txt .
RUN chown --recursive root:htb-console /home/htb-console && \
    chmod --recursive 750 /home/htb-console && \
    chmod 740 /home/htb-console/flag.txt

EXPOSE 4444
USER htb-console
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./htb-console",stderr; \
    done
