#!/bin/sh
set -x

cat > /conf.json <<_EOF_
{
  "keystorePath" : "/monarca.jks",
  "keystorePassword" : "${IADB_JKS_PASS}",
  "clientId" : "${IADB_CLIENT_ID}",
  "clientSecret" : "${IADB_CLIENT_SECRET}",
  "citiHost" : "${IADB_CITI_HOST}",
  "tokenPath" : "${IADB_TOKEN_PATH}",
  "allowedOriginPattern" : "${IADB_ALLOWED_ORIGIN_PATTERN:-*}",
  "citiConnectRequestTimeout" : ${IADB_CITI_CONNECT_TIMEOUT:-20000}
}
_EOF_

export CITI_PROXY_OPTS="-Dlogback.configurationFile=file:/citi-proxy/logback.xml"
/citi-proxy/bin/citi-proxy run org.iadb.tech.MainVerticle -conf /conf.json
