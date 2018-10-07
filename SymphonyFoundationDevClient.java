package com.baulsupp.s11c;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import static java.net.http.HttpRequest.BodyPublishers.ofString;
import static java.net.http.HttpResponse.BodyHandlers.ofString;

public class SymphonyFoundationDevClient {
    public static void main(String[] args) throws Exception {
        String pod = "foundation-dev";
        File keystore = new File(System.console().readLine("Keystore: "));
        String keyPass = System.console().readLine("Password: ");
        String targetUsername = System.console().readLine("Target User: ");
        boolean debug = false;
        boolean sslDebug = false;

        sendTestRequest(keyPass, keystore, pod, targetUsername, debug, sslDebug);
    }

    private static void sendTestRequest(String keyPass, File keystore, String pod, String targetUsername, boolean debug, boolean sslDebug) throws Exception {
        if (sslDebug) {
            System.setProperty("javax.net.debug", "ssl,handshake");
        }

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream ksStream = new FileInputStream(keystore)) {
            ks.load(ksStream, keyPass.toCharArray());
        }

        String keyName = ks.aliases().nextElement();

        System.out.println("keyName\t\t\t" + keyName);

        if (debug) {
            X509Certificate cert = (X509Certificate) ks.getCertificate(keyName);
            System.out.println(cert);
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, keyPass.toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        HttpClient authClient = HttpClient.newBuilder().sslContext(context).build();

        HttpResponse<String> authResponse = authClient.send(postRequest("https://" + pod + "-api.symphony.com/sessionauth/v1/authenticate", "{}", true), ofString());
        String sessionToken = extractField(authResponse, "token");
        System.out.println("sessionToken\t\t" + sessionToken + ".");

        HttpResponse<String> keyResponse = authClient.send(postRequest("https://" + pod + "-api.symphony.com/keyauth/v1/authenticate", "{}", true), ofString());
        String keyManagerToken = extractField(keyResponse, "token");
        System.out.println("keyManagerToken\t\t" + keyManagerToken + ".");

        HttpClient client = HttpClient.newHttpClient();

        HttpResponse<String> userResponse = client.send(authenticatedGetRequest("https://" + pod + ".symphony.com/pod/v2/user?username=" + targetUsername, sessionToken, keyManagerToken), ofString());
        long targetId = extractLongField(userResponse, "id");

        System.out.println("target\t\t\t" + targetId);

        HttpResponse<String> createResponse = client.send(authenticatedPostRequest("https://" + pod + ".symphony.com/pod/v1/im/create", "[" + targetId + "]", true, sessionToken, keyManagerToken), ofString());
        String stream = extractField(createResponse, "id");

        System.out.println("stream\t\t\t" + stream);

        HttpResponse<String> messageResponse = client.send(authenticatedPostRequest("https://" + pod + ".symphony.com/agent/v2/stream/" + stream + "/message/create", "{\"message\":\"Hello world!\", \"format\":\"TEXT\"}", true, sessionToken, keyManagerToken), ofString());
        checkResponse(messageResponse);
    }

    private static String extractField(HttpResponse<String> response, String field) {
        checkResponse(response);
        String body = response.body();
        return body.replaceFirst(".*\"" + field + "\":\"([^\"]+)\".*", "$1").trim();
    }

    private static long extractLongField(HttpResponse<String> response, String field) {
        checkResponse(response);
        String body = response.body();
        return Long.valueOf(body.replaceFirst(".*\"" + field + "\":([\\d]+).*", "$1").trim());
    }

    private static void checkResponse(HttpResponse<String> response) {
        if (response.statusCode() != 200) {
            System.err.println(response);
            System.exit(-1);
        }
    }

    private static HttpRequest authenticatedGetRequest(String url, String sessionToken, String keyManagerToken) {
        return HttpRequest.newBuilder().uri(URI.create(url)).header("sessionToken", sessionToken).header("keyManagerToken", keyManagerToken).build();
    }

    private static HttpRequest postRequest(String url, String body, boolean json) {
        return HttpRequest.newBuilder().uri(URI.create(url)).POST(ofString(body)).header("Content-Type", json ? "application/json" : "application/x-www-form-urlencoded").build();
    }

    private static HttpRequest authenticatedPostRequest(String url, String body, boolean json, String sessionToken, String keyManagerToken) {
        return HttpRequest.newBuilder().uri(URI.create(url)).POST(ofString(body)).header("sessionToken", sessionToken).header("keyManagerToken", keyManagerToken).header("Content-Type", json ? "application/json" : "application/x-www-form-urlencoded").build();
    }
}
