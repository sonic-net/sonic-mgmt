FROM soniccr1.azurecr.io/debian:buster

RUN apt-get update
RUN apt-get install procps
WORKDIR /root
COPY Agent.Worker /bin/
COPY start.sh /bin/
ENTRYPOINT ["/bin/start.sh"]