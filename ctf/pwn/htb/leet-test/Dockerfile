FROM ubuntu

RUN apt-get update --yes && apt-get install --yes \
    socat

RUN useradd --create-home leet_test

WORKDIR /home/leet_test
COPY leet_test .
COPY flag.txt .
RUN chown --recursive root:leet_test /home/leet_test && \
    chmod --recursive 750 /home/leet_test && \
    chmod 740 /home/leet_test/flag.txt

EXPOSE 4444
USER leet_test
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./leet_test",stderr; \
    done
