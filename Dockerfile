FROM adoptopenjdk:11-jre-hotspot

RUN apt-get update && apt-get install -y \
    unzip \
 && rm -rf /var/lib/apt/lists/*

COPY build/distributions/citi-proxy.zip /citi-proxy.zip
RUN unzip /citi-proxy.zip

COPY docker/citi-entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
