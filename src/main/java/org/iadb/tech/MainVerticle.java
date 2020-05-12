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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class MainVerticle extends AbstractVerticle {

    private static final Logger logger = LoggerFactory.getLogger(MainVerticle.class);

    @Override
    public void start() throws Exception {
        logger.debug("Config: \n {}", config().encodePrettily());

        String keystorePath = config().getString("keystorePath");
        String keystorePassword = config().getString("keystorePassword");
        String clientId = config().getString("clientId");
        String clientSecret = config().getString("clientSecret");
        String citiHost = config().getString("citiHost");

        vertx.deployVerticle(new TokenHandlerVerticle());
        vertx.deployVerticle(
                new CitiConnectVerticle(
                        vertx.fileSystem().readFileBlocking(keystorePath),
                        keystorePassword,
                        clientId,
                        clientSecret,
                        citiHost
                )
        );

        HttpServer server = vertx.createHttpServer();
        Router router = Router.router(vertx);
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
                                .put("request", routingContext.getBodyAsString()),
                            (Handler<AsyncResult<Message<String>>>) citiConnect -> {
                                if (citiConnect.succeeded()) {
                                    response
                                        .putHeader(HttpHeaders.CONTENT_TYPE, "application/xml")
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
