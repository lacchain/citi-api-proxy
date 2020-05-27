package org.iadb.tech;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.eventbus.Message;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.CorsHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CitiProxyServerVerticle extends AbstractVerticle {

    private static final Logger logger = LoggerFactory.getLogger(CitiProxyServerVerticle.class);

    private final String allowedOriginPattern;

    public CitiProxyServerVerticle(String allowedOriginPattern) {
        this.allowedOriginPattern = allowedOriginPattern;
    }

    @Override
    public void start() {
        HttpServer server = vertx.createHttpServer();
        Router router = Router.router(vertx);
        router.route().handler(CorsHandler.create(allowedOriginPattern));
        router.route().handler(BodyHandler.create());
        router.route().handler(routingContext -> {
            String citiConnectPath = routingContext.request().path();
            HttpServerResponse response = routingContext.response();
            vertx.eventBus().request(
                    "get_token", null,
                    (Handler<AsyncResult<Message<String>>>) getToken -> {
                        if (getToken.succeeded()) {
                            vertx.eventBus().request(
                                    "citi_connect",
                                    new JsonObject()
                                            .put("uri", citiConnectPath)
                                            .put("token", getToken.result().body())
                                            .put("http-method", routingContext.request().rawMethod())
                                            .put("request", routingContext.getBodyAsString()),
                                    (Handler<AsyncResult<Message<String>>>) citiConnect -> {
                                        if (citiConnect.succeeded()) {
                                            String statusCode = citiConnect.result().headers().get(CitiConnectVerticle.HEADER_STATUS_CODE);
                                            String statusMessage = citiConnect.result().headers().get(CitiConnectVerticle.HEADER_STATUS_MESSAGE);
                                            citiConnect.result().headers().remove(CitiConnectVerticle.HEADER_STATUS_CODE).remove(CitiConnectVerticle.HEADER_STATUS_MESSAGE);

                                            response.headers().addAll(citiConnect.result().headers());
                                            response.setStatusCode(Integer.parseInt(statusCode))
                                                    .setStatusMessage(statusMessage)
                                                    .end(citiConnect.result().body());
                                        } else {
                                            response.setStatusCode(500).setStatusMessage("Internal Server Error").end();
                                        }
                                    }
                            );
                        } else {
                            response.setStatusCode(500).setStatusMessage("Internal Server Error").end();
                        }
                    }
            );
        });

        server.requestHandler(router).listen(8080, listen -> {
            if (listen.succeeded()) {
                logger.info("Server is now listening!");
            } else {
                logger.error("Failed to bind!", listen.cause());
            }
        });
    }
}
