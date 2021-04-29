FROM ubuntu

RUN apt-get update --yes && apt-get install --yes \
    socat

RUN useradd --create-home reg

WORKDIR /home/reg
COPY reg .
COPY flag.txt .
RUN chown --recursive root:reg /home/reg && \
    chmod --recursive 750 /home/reg && \
    chmod 740 /home/reg/flag.txt

EXPOSE 4444
USER reg
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./reg",stderr; \
    done
