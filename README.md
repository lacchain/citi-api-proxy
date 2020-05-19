# CitiConnect - IADB Proxy

## Java KeyStore structure
This proxy uses a single JKS file for handling keys and certificates and it must have the following structure.

  * alias **1**: key and certificate for SSL client authentication
  * alias **payload**: key and certificate for decrypting response and signing request
  * alias **citi**: Citi certificate for encrypting request
  * alias **citi-sign**: Citi certificate for validating response signature

### Example for generating a Java KeyStore
Every certificate and key pair must be converted to PKCS#12 format before storing them into the Java KeyStore.
```shell
$ openssl pkcs12 -export -in ssl.crt -inkey ssl.key -out ssl.p12
$ keytool -importkeystore -srckeystore ssl.p12 -srcstoretype pkcs12 -srcalias 1 -destkeystore monarca.jks -deststoretype jks -destalias 1
```
You need to set a password for the key store.
```shell
$ openssl pkcs12 -export -in client.crt -inkey client.key -out client.p12
$ keytool -importkeystore -srckeystore client.p12 -srcstoretype pkcs12 -srcalias 1 -destkeystore monarca.jks -deststoretype jks -destalias payload
```
Then you need to add both certificates.
```shell
$ keytool -importcert -file citi.pem -keystore monarca.jks  -alias "citi"
$ keytool -importcert -file citi-sign.pem -keystore monarca.jks  -alias "citi-sign"
```
Everytime you want to interact with the key store you'll be asked for the password you entered in the first step.

## Running as a Docker container
The Docker image expects a zip distribution of the `citi-proxy` project. You can build it running
```shell
$ ./gradlew clean distZip
$ docker build . -t citi-proxy
```
The container expects mounted in `/monarca.jks` the Java KeyStore configured accordingly the previous section. Also, the following variables must be properly setup
  * **IADB_JKS_PASS**: the key store password
  * **IADB_CLIENT_ID**: the assigned client ID
  * **IADB_CLIENT_SECRET**: the assigned client secret
  * **IADB_CITI_HOST**: the host for redirecting the requests
  * **IADB_ALLOWED_ORIGIN_PATTERN**: the allowed origin pattern for [CORS](http://www.w3.org/TR/cors/) support (Default: `*`)
  * **IADB_CITI_CONNECT_TIMEOUT**: the timeout, in millis, for every CitiConnect request (Default: `20000`)

Once started, the server will listen in the port 8080

### Docker run example
```shell
$ docker run -ti -p 8080:8080 -v /local/path/to/monarca.jks:/monarca.jks -e IADB_JKS_PASS="00000001" -e IADB_CLIENT_ID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" -e IADB_CLIENT_SECRET="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" -e IADB_CITI_HOST="testing.citi.com" citi-proxy
``` 
## How to use the proxy
This proxy provides transparent access to CITI Connect APIs (W3C XML Digital Signatures and Encryption only). E.g., if you need to access to https://{CITI_HOST}/citiconnect/{env_name2}/paymentservices/v1/payment/enhancedinquiry, you should send the proper plain XML to http://localhost:8080/citiconnect/{env_name2}/paymentservices/v1/payment/enhancedinquiry and the proxy will take care of handling authentication tokens, encryption of the request and desencryption of the response.
