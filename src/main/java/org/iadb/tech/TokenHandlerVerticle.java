package org.iadb.tech;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.eventbus.EventBus;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;

public class TokenHandlerVerticle extends AbstractVerticle {

    private static final Logger logger = LoggerFactory.getLogger(TokenHandlerVerticle.class);
    private static final String OAUTH_REQUEST = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<oAuthToken\n" +
            "    xmlns=\"http://com.citi.citiconnect/services/types/oauthtoken/v1\">\n" +
            "    <grantType>client_credentials</grantType>\n" +
            "    <scope>/authenticationservices/v1</scope>\n" +
            "    <sourceApplication>CCF</sourceApplication>\n" +
            "</oAuthToken>";
    private Token currentToken;

    @Override
    public void start() throws Exception {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder tokenResponseBuilder = documentBuilderFactory.newDocumentBuilder();

        EventBus eventBus = vertx.eventBus();
        eventBus.consumer("get_token", (Handler<Message<JsonObject>>) event -> {
            logger.debug("get_token -> (currentToken: {})", currentToken);
            if (currentToken != null && !currentToken.isExpired()) {
                event.reply(currentToken.getValue());
            } else {
                if (currentToken != null) {
                    logger.info("OAuth token expired, requesting a new one");
                }
                eventBus.request(
                    "citi_connect",
                    new JsonObject()
                            .put("uri", "/citiconnect/sb/authenticationservices/v2/oauth/token")
                            .put("request", OAUTH_REQUEST),
                    (Handler<AsyncResult<Message<String>>>) reply -> {
                        if (reply.succeeded()) {
                            logger.info("Oauth request response headers {}", reply.result().headers());
                            try {
                                Document tokenResponse = tokenResponseBuilder.parse(new ByteArrayInputStream(reply.result().body().getBytes()));
                                String tokenValue = tokenResponse.getElementsByTagName("access_token").item(0).getTextContent();
                                Long lifetime = Long.valueOf(tokenResponse.getElementsByTagName("expires_in").item(0).getTextContent());

                                currentToken = new Token(tokenValue, lifetime);
                                logger.info("New OAuth token: {}", currentToken);
                                event.reply(tokenValue);
                            } catch (Exception e) {
                                logger.error("Unable to parse token response", e);
                                event.fail(-1, e.getMessage());
                            }
                        } else {
                            logger.error("citi_connect for token failed", reply.cause());
                            event.fail(-1, reply.cause().getMessage());
                        }
                    }
                );
            }
        });
    }

    private static class Token {

        private final String value;
        private final Long lifetime;
        private final Long created;

        public Token(String value, Long lifetime) {
            this.value = value;
            this.lifetime = lifetime;
            this.created = System.currentTimeMillis();
        }

        public boolean isExpired() {
            return (System.currentTimeMillis() - created) / 1000 >= lifetime;
        }

        public String getValue() {
            return value;
        }

        @Override
        public String toString() {
            return "Token{" +
                    "value='****** (size:" + value.length() + ")'" +
                    ", lifetime=" + lifetime +
                    ", created=" + created +
                    '}';
        }
    }
}
