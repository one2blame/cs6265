FROM ubuntu

RUN apt-get update --yes && apt-get install --yes \
    socat

RUN useradd --create-home nightmare

WORKDIR /home/nightmare
COPY nightmare .
COPY flag.txt .
RUN chown --recursive root:nightmare /home/nightmare && \
    chmod --recursive 750 /home/nightmare && \
    chmod 740 /home/nightmare/flag.txt

EXPOSE 4444
USER nightmare
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./nightmare",stderr; \
    done
