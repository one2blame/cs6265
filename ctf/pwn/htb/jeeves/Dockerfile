FROM ubuntu

RUN apt-get update --yes && apt-get install --yes \
    socat

RUN useradd --create-home jeeves

WORKDIR /home/jeeves
COPY jeeves .
COPY flag.txt .
RUN chown --recursive root:jeeves /home/jeeves && \
    chmod --recursive 750 /home/jeeves && \
    chmod 740 /home/jeeves/flag.txt

EXPOSE 4444
USER jeeves
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./jeeves",stderr; \
    done
