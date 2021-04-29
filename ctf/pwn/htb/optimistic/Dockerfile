FROM ubuntu

RUN apt-get update --yes && apt-get install --yes \
    socat

RUN useradd --create-home optimistic

WORKDIR /home/optimistic
COPY optimistic .
COPY flag.txt .
RUN chown --recursive root:optimistic /home/optimistic && \
    chmod --recursive 750 /home/optimistic && \
    chmod 740 /home/optimistic/flag.txt

EXPOSE 4444
USER optimistic
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./optimistic",stderr; \
    done
