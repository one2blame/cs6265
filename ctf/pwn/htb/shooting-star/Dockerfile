FROM ubuntu

RUN apt-get update --yes && apt-get install --yes \
    socat

RUN useradd --create-home shooting_star

WORKDIR /home/shooting_star
COPY shooting_star .
COPY flag.txt .
RUN chown --recursive root:shooting_star /home/shooting_star && \
    chmod --recursive 750 /home/shooting_star && \
    chmod 740 /home/shooting_star/flag.txt

EXPOSE 4444
USER shooting_star
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./shooting_star",stderr; \
    done
