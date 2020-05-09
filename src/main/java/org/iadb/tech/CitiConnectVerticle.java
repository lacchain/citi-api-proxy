package org.iadb.tech;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.eventbus.Message;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.JksOptions;
import io.vertx.ext.web.client.HttpRequest;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.crypto.KeyGenerator;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.security.*;
import java.security.cert.X509Certificate;

public class CitiConnectVerticle extends AbstractVerticle {

    private static final Logger logger = LoggerFactory.getLogger(CitiConnectVerticle.class);
    private static final String REQUEST_JKS_ALIAS = "payload";
    private static final String CITI_JKS_ALIAS = "citi";
    private static final String CITI_SIGN_JKS_ALIAS = "citi-sign";

    static {
        org.apache.xml.security.Init.init();
    }

    private final PrivateKey requestSignKey;
    private final X509Certificate requestCertificate;
    private final X509Certificate citiCertificate;
    private final X509Certificate citiSignCertificate;
    private final String clientId;
    private final String clientSecretKey;
    private final String citiHost;
    private final JksOptions keyStoreOptions;
    private final DocumentBuilder documentBuilder;

    public CitiConnectVerticle(Buffer keystoreBuffer, String keystorePassword, String clientId, String clientSecretKey, String citiHost) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new ByteArrayInputStream(keystoreBuffer.getBytes()), keystorePassword.toCharArray());

        this.requestSignKey = (PrivateKey) ks.getKey(REQUEST_JKS_ALIAS, keystorePassword.toCharArray());
        this.requestCertificate = (X509Certificate) ks.getCertificate(REQUEST_JKS_ALIAS);
        this.requestCertificate.checkValidity();
        this.citiCertificate = (X509Certificate) ks.getCertificate(CITI_JKS_ALIAS);
        this.citiCertificate.checkValidity();
        this.citiSignCertificate = (X509Certificate) ks.getCertificate(CITI_SIGN_JKS_ALIAS);
        this.citiSignCertificate.checkValidity();
        this.keyStoreOptions = new JksOptions().setValue(keystoreBuffer).setPassword(keystorePassword);
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "ds");
        this.documentBuilder = documentBuilderFactory.newDocumentBuilder();
        this.clientId = clientId;
        this.clientSecretKey = clientSecretKey;
        this.citiHost = citiHost;
    }

    @Override
    public void start() throws Exception {
        WebClient webClient = WebClient.create(vertx, new WebClientOptions()
                .setDefaultPort(443)
                .setDefaultHost(citiHost)
                .setSsl(true)
                .setKeyStoreOptions(keyStoreOptions));

        vertx.eventBus().consumer("citi_connect", (Handler<Message<JsonObject>>) event -> {
            JsonObject body = event.body();
            logger.debug("citi_connect -> {}", body.encodePrettily());
            String uri = body.getString("uri");

            HttpRequest<Buffer> request = webClient.post(uri)
                    .addQueryParam("client_id", clientId)
                    .putHeader(HttpHeaders.CONTENT_TYPE.toString(), "application/xml");
            if (body.containsKey("token")) {
                request = request.bearerTokenAuthentication(body.getString("token"));
            } else {
                request = request.basicAuthentication(clientId, clientSecretKey);
            }

            try {
                Document requestDocument = documentBuilder.parse(new ByteArrayInputStream(body.getString("request").getBytes()));
                Document encryptedRequestDocument  = encryptXml(requestDocument, requestSignKey, requestCertificate, citiCertificate);
                request.sendBuffer(Buffer.buffer(toString(encryptedRequestDocument)), ar -> {
                    if (ar.succeeded()) {
                        try {
                            Document encryptedResponseDocument = documentBuilder.parse(new ByteArrayInputStream(ar.result().body().getBytes()));
                            Document responseDocument = decryptXml(encryptedResponseDocument, requestSignKey);
                            //verifySignature(responseDocument, citiSignCertificate);
                            event.reply(toString(responseDocument));
                        } catch (Exception e) {
                            logger.error("Response generation document failed", e);
                            event.fail(-1, e.getMessage());
                        }
                    } else {
                        logger.error("Request failed", ar.cause());
                        event.fail(-1, ar.cause().getMessage());
                    }
                });
            } catch (Exception e) {
                logger.error("Request generation document failed", e);
                event.fail(-1, e.getMessage());
            }
        });
    }

    private Document encryptXml(Document xmlDoc, PrivateKey privateSignKey, X509Certificate signCert, X509Certificate encryptCert) throws Exception {
        Element root = xmlDoc.getDocumentElement();
        XMLSignature sig = new XMLSignature(xmlDoc, "file:", XMLSignature.ALGO_ID_SIGNATURE_RSA);
        root.appendChild(sig.getElement());
        Transforms transforms = new Transforms(xmlDoc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

        KeyInfo info = sig.getKeyInfo();
        X509Data x509data = new X509Data(xmlDoc);
        x509data.add(new XMLX509IssuerSerial(xmlDoc, signCert));
        x509data.add(new XMLX509Certificate(xmlDoc, signCert));
        info.add(x509data);

        sig.sign(privateSignKey);

        PublicKey publicEncryptKey = encryptCert.getPublicKey();

        String jceAlgorithmName = "DESede";
        KeyGenerator keyGenerator = KeyGenerator.getInstance(jceAlgorithmName);
        Key symmetricKey = keyGenerator.generateKey();
        String algorithmURI = XMLCipher.RSA_v1dot5;
        XMLCipher keyCipher = XMLCipher.getInstance(algorithmURI);
        keyCipher.init(XMLCipher.WRAP_MODE, publicEncryptKey);
        EncryptedKey encryptedKey = keyCipher.encryptKey(xmlDoc, symmetricKey);
        Element rootElement = xmlDoc.getDocumentElement();
        algorithmURI = XMLCipher.TRIPLEDES;
        XMLCipher xmlCipher = XMLCipher.getInstance(algorithmURI);
        xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);
        EncryptedData encryptedData = xmlCipher.getEncryptedData();
        KeyInfo keyInfo = new KeyInfo(xmlDoc);
        keyInfo.add(encryptedKey);
        encryptedData.setKeyInfo(keyInfo);
        xmlCipher.doFinal(xmlDoc, rootElement, false);

        return xmlDoc;
    }

    private Document decryptXml(Document encryptedXml, PrivateKey privateDecryptKey) throws Exception {
        Element docRoot = encryptedXml.getDocumentElement();
        Node dataEL;
        Node keyEL;
        if ("http://www.w3.org/2001/04/xmlenc#".equals(docRoot.getNamespaceURI())
                && "EncryptedData".equals(docRoot.getLocalName())) {
            dataEL = docRoot;
        } else {
            NodeList childs = docRoot.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "EncryptedData");
            if (childs == null || childs.getLength() == 0) {
                throw new Exception("Encrypted Data not found on XML Document while parsing to decrypt");
            }
            dataEL = childs.item(0);
        }
        if (dataEL == null) {
            throw new Exception("Encrypted Data not found on XML Document while parsing to decrypt");
        }
        NodeList keyList = ((Element) dataEL).getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#",
                "EncryptedKey");
        if (keyList == null || keyList.getLength() == 0) {
            throw new Exception("Encrypted Key not found on XML Document while parsing to decrypt");
        }
        keyEL = keyList.item(0);
        XMLCipher cipher = XMLCipher.getInstance();
        cipher.init(XMLCipher.DECRYPT_MODE, null);
        EncryptedData encryptedData = cipher.loadEncryptedData(encryptedXml, (Element) dataEL);
        EncryptedKey encryptedKey = cipher.loadEncryptedKey(encryptedXml, (Element) keyEL);

        Document decryptedDoc = null;
        if (encryptedData != null && encryptedKey != null) {
            String encAlgoURL = encryptedData.getEncryptionMethod().getAlgorithm();
            XMLCipher keyCipher = XMLCipher.getInstance();
            keyCipher.init(XMLCipher.UNWRAP_MODE, privateDecryptKey);
            Key encryptionKey = keyCipher.decryptKey(encryptedKey, encAlgoURL);
            cipher = XMLCipher.getInstance();
            cipher.init(XMLCipher.DECRYPT_MODE, encryptionKey);
            decryptedDoc = cipher.doFinal(encryptedXml, (Element) dataEL);
        }
        decryptedDoc.normalize();
        return decryptedDoc;
    }

    private void verifySignature(Document decryptedDoc, X509Certificate signVerifyCert) throws Exception {
        boolean verifySignStatus = false;
        NodeList sigElement = decryptedDoc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#",
                "Signature");
        if (sigElement == null || sigElement.getLength() == 0) {
            throw new Exception("No XML Digital Signature Found - unable to check the signature");
        } else {
            String BaseURI = "file:";
            XMLSignature signature = new XMLSignature((Element) sigElement.item(0), BaseURI);

            KeyInfo keyInfo = signature.getKeyInfo();
            if (keyInfo == null) {
                throw new Exception("Could not locate KeyInfo element - unable to check the signature");
            } else {
                if (keyInfo.containsX509Data()) {
                    X509Certificate certFromDoc = keyInfo.getX509Certificate();
                    if (certFromDoc != null) {
                        int enCodeCertLengthFrmDocCert = certFromDoc.getEncoded().length;
                        int enCodeCertLengthTobeValidated = signVerifyCert.getEncoded().length;
                        if (enCodeCertLengthFrmDocCert == enCodeCertLengthTobeValidated) {
                            verifySignStatus = signature.checkSignatureValue(signVerifyCert);
                        } else {
                            throw new Exception(
                                    "Signature Verification Failed as Cert available in XML & configured on Plugin Properties are different");
                        }
                    }
                } else {
                    PublicKey pk = keyInfo.getPublicKey();
                    if (pk != null) {
                        verifySignStatus = signature.checkSignatureValue(signVerifyCert);
                    } else {
                        throw new Exception("X509 cert and PublicKey not found on signature of XML");
                    }
                }
            }
            Element element = (Element) decryptedDoc
                    .getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);
            element.getParentNode().removeChild(element);
        }
        if (!verifySignStatus) {
            throw new Exception("XML Signature Verification Failed");
        }
    }

    private String toString(Document encryptedRequest) throws TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(encryptedRequest), new StreamResult(writer));

        return writer.getBuffer().toString();
    }

}
