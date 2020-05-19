package org.iadb.tech;

import io.vertx.core.AbstractVerticle;
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
        vertx.deployVerticle(new CitiProxyServerVerticle());
    }
}
