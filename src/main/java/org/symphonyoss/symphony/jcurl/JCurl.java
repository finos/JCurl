/*
 * Copyright 2016-2017 MessageML - Symphony LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.symphonyoss.symphony.jcurl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * <h1>JSON-aware curl (1) in Java</h1>
 * <b>Usage</b>
 * <pre>
 * //Get a session token
 *
 * JCurl jcurl = JCurl.builder()
 * .method(JCurl.HttpMethod.POST)
 * .keystore("bot.user1.p12")      //Set user certificate for authentication
 * .storepass("changeit")
 * .storetype("pkcs12")
 * .extract("skey", "token")       //Extract the value of the JSON tag "token" to a map entry under "skey"
 * .build();
 *
 * HttpURLConnection connection = jcurl.connect("https://localhost.symphony.com:8444/sessionauth/v1/authenticate");
 * JCurl.Response response = jcurl.processResponse(connection);
 * String sessionToken = response.getTag("skey");  //Retrieve the extracted tag saved as "skey"
 *
 * //Get session info (returns the requesting user ID)
 *
 * jcurl = JCurl.builder()
 * .method(JCurl.HttpMethod.GET)               //HTTP GET is the default; this line can be skipped
 * .header("sessionToken", sessionToken)       //Set the session token in the request header
 * .extract("uid", "userId")                   //Extract the user ID from the response as "uid"
 * .build();
 *
 * connection = jcurl.connect("https://localhost.symphony.com:8443/pod/v1/sessioninfo");
 * response = jcurl.processResponse(connection);
 * String userId = response.getTag("uid");
 *
 * System.out.println("User ID: " + userId);
 *
 * //Create an IM with user 123456
 *
 * jcurl = JCurl.builder()
 * .method(JCurl.HttpMethod.POST)              //Set implicitly by specifying ".data()"; this line can be skipped
 * .header("sessionToken", sessionToken)       //Set the session token in the request header
 * .data("[123456]")                           //Set the JSON payload of the request
 * .extract("sid", "id")                       //Extract the stream ID of the conversation as "sid"
 * .build();
 *
 * connection = jcurl.connect("https://localhost.symphony.com:8443/pod/v1/im/create");
 * response = jcurl.processResponse(connection);
 * String streamId = response.getTag("sid");
 *
 * System.out.println("Stream ID: " + streamId);
 *
 * //Print the output of the call
 * System.out.println(response.getOutput());       //Prints '{"id": "wFwupr-KY3QW1oEkjE61x3___qsvcXdFdA"}'
 * </pre>
 * @author bruce.skingle
 * @author ldrozdz
 * @version $Id: $Id
 */
public class JCurl {

  private String url;
  private String data;
  private String keyStore;
  private String storeType;
  private String storePass;
  private String trustStore;
  private String trustType;
  private String trustPass;
  private String proxyHost;
  private String proxyPort;
  private String nonProxyHosts;
  private int verbosity;
  private PrintStream outStream = System.out ;
  private PrintStream errStream = System.err ;
  private int connectTimeout;
  private int readTimeout;
  private boolean trustAllHostnames;
  private boolean trustAllCerts;
  private boolean extractCookies;
  private List<String> tagList = new ArrayList<>();
  private Map<String, String> tagMap = new HashMap<>();
  private Map<String, String> formMap = new HashMap<>();
  private Map<String, String> headerMap = new HashMap<>();
  private Map<String, String> queryMap = new HashMap<>();
  private Map<String, String> cookieMap = new HashMap<>();
  private Set<Integer> expectedResponseSet = new HashSet<>();
  private HttpMethod method = HttpMethod.GET;
  private String contentType = "application/json";

  static final ObjectMapper MAPPER = new ObjectMapper();
  static final HostnameVerifier DEFAULT_HOSTNAME_VERIFIER = HttpsURLConnection.getDefaultHostnameVerifier();

  public enum HttpMethod {
    GET, POST, PUT, DELETE, HEAD, CONNECT, OPTIONS
  }

  /**
   * <p>Entry point for command-line usage. Call <code>java -jar jcurl.jar</code> for usage info.</p>
   *
   * @param argv an array of {@link java.lang.String} objects.
   * @throws java.io.IOException if any.
   * @throws java.security.cert.CertificateParsingException if any.
   * @throws java.security.KeyManagementException if any.
   * @throws java.security.NoSuchAlgorithmException if any.
   */
  public static void main(String[] argv)
      throws IOException, CertificateParsingException, KeyManagementException, NoSuchAlgorithmException {
    ConfigParser config = new ConfigParser();
    JCurl jcurl = config.parseCommandLine(argv);
    HttpURLConnection con = jcurl.connect(config.url);
    Response response = jcurl.processResponse(con);
    response.print();
  }

  /**
   * <p>Create a builder.</p>
   *
   * @return a {@link org.symphonyoss.symphony.jcurl.JCurl.Builder} object.
   */
  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private JCurl instance;

    private Builder() {
      //Reset hostname/certificate verifiers to defaults for repeated programmatic uses
      HttpsURLConnection.setDefaultHostnameVerifier(DEFAULT_HOSTNAME_VERIFIER);
//      HttpsURLConnection.setDefaultSSLSocketFactory(DEFAULT_SSL_SOCKET_FACTORY);

      instance = new JCurl();
    }

    /**
     * Set the HTTP type of the request. If not set, JCurl uses {@link HttpMethod#GET}.
     * @param method
     * @return
     */
    public Builder method(HttpMethod method) {
      instance.method = method;
      return this;
    }

    /**
     * Send a POST request with DATA as request body. <br>
     * Example: {@link #data(String) data("{\"message\": \"Hello world!\", \"format\": \"TEXT\"}"}.
     * @param payload
     * @return
     */
    public Builder data(String payload) {
      instance.data = payload;
      instance.method = HttpMethod.POST;
      return this;
    }

    /**
     * Send a custom header with the request. <br>
     * Example: {@link #header(String, String) header("Content-Type", "application/json")}.
     * @param name
     * @param value
     * @return
     */
    public Builder header(String name, String value) {
      if (name.toLowerCase().equals("content-type")) {
        instance.contentType = value.toLowerCase();
      } else {
        instance.headerMap.put(name, value);
      }
      return this;
    }

    /**
     * Send a POST request with CONTENT as "key=value" pairs corresponding to a HTML form.
     * To specify a file, precede the file name with \"@\" (example:
     * {@link #form(String, String) form("file", "@/my/test/file.txt"}). <br>
     * Sets 'Content-Type: multipart/form-data'.
     * @param name
     * @param value
     * @return
     */
    public Builder form(String name, String value) {
      instance.formMap.put(name, value);
      instance.method = HttpMethod.POST;
      return this;
    }

    /**
     * Set request query parameters to be appended to the target URL as "name=value" pairs separated by "&";
     * @param name
     * @param value
     * @return
     */
    public Builder query(String name, String value) {
      instance.queryMap.put(name, value);
      return this;
    }

    /**
     * Send a custom cookie with the request. <br>
     * @param name
     * @param value
     * @return
     */
    public Builder cookie(String name, String value) {
      instance.cookieMap.put(name, value);
      return this;
    }

    /**
     * Extract cookies returned by the call as KEY=VALUE pairs.
     * @param extract
     * @return
     */
    public Builder extractCookies(boolean extract) {
      instance.extractCookies = extract;
      return this;
    }

    /**
     * Extract NODE from a JSON object returned by the call and return as "LABEL=NODE". Use "." to navigate within the
     * JSON tree.<br>
     * Example: {@link #extract(String) extract("uid", "userSystemInfo.id")} (returns \"uid=12345\").")
     * @param label
     * @param node
     * @return
     */
    public Builder extract(String label, String node) {
      instance.tagMap.put(label, node);
      return this;
    }

    /**
     * Iterate over a JSON array of objects returned by the call content and extract the value of NODE. See {@link
     * #extract(String, String)} for more details.
     * @param node
     * @return
     */
    public Builder extract(String node) {
      instance.tagList.add(node);
      return this;
    }

    /**
     * Add HTTP STATUS as an expected response code. By default only HTTP 200 is expected as correct status.
     * @param expectedStatus
     * @return
     */
    public Builder expect(int expectedStatus) {
      instance.expectedResponseSet.add(expectedStatus);
      return this;
    }

    /**
     * Output verbosity. Currently 4 levels are recognised:<br>
     *
     * 0 (default): only displays response content<br>
     * 1: adds request and response details<br>
     * 2: adds certificate details.<br>
     * 3: turns on SSL debugging.
     * @param level
     * @return
     */
    public Builder verbosity(int level) {
      instance.verbosity = level;
      return this;
    }
	
    /**
     * Redirect standard output to the given stream
     *
     * @param stream
     * @return
     */
    public Builder output(PrintStream stream) {
      instance.outStream = stream;
      return this;
    }

    /**
     * Redirect error output to the given stream
     *
     * @param stream
     * @return
     */
    public Builder error(PrintStream stream) {
      instance.errStream = stream;
      return this;
    }

    /**
     * The keystore containing the certificate to use for authentication.
     * @param store
     * @return
     */
    public Builder keystore(String store) {
      instance.keyStore = store;
      return this;
    }

    /**
     * The keystore type. Supported values: jks, jceks, pkcs11, pkcs12, bks, dks, windows-my.
     * @param type
     * @return
     */
    public Builder storetype(String type) {
      instance.storeType = type;
      return this;
    }

    /**
     * The keystore password.
     */
    public Builder storepass(String pass) {
      instance.storePass = pass;
      return this;
    }

    /**
     * The truststore containing the server certificate. If unspecified, the default Java truststore (cacerts) is used.
     * @param store
     * @return
     */
    public Builder truststore(String store) {
      instance.trustStore = store;
      return this;
    }

    /**
     * The truststore type. Supported values: jks, jceks, pkcs11, pkcs12, bks, dks, windows-my.
     * @param type
     * @return
     */
    public Builder trusttype(String type) {
      instance.trustType = type;
      return this;
    }

    /**
     * The truststore password.
     * @param pass
     * @return
     */
    public Builder trustpass(String pass) {
      instance.trustPass = pass;
      return this;
    }

    /**
     * Proxy the request through the specified URL. Applies to all protocols unless excluded with "-noproxy".<br>
     * Example: {@link #proxy(String) proxy("https://my.proxy.com:8080")}
     * @param proxy
     * @return
     */
    public Builder proxy(String proxy) throws MalformedURLException {
      URL url = new URL(proxy);

      instance.proxyHost = url.getHost();
      instance.proxyPort = String.valueOf(url.getPort());

      return this;
    }

    /**
     * Bypass the proxy (if defined) for the specified list of |-separated hosts. Supports wildcards.
     * Example: {@link #nonProxyHosts(String) nonProxyHosts("my.host.org|*.otherhost.net")}.
     * @param hosts
     * @return
     */
    public Builder nonProxyHosts(String hosts) {
      instance.nonProxyHosts = hosts;
      return this;
    }

    /**
     * Disable checks for an HTTPS request. Combines {@link #trustAllHostnames(boolean) trustAllHostnames(true)}
     * and {@link #trustAllCertificates(boolean) trustAllCertificates(true)}.
     * @param disableChecks
     * @return
     */
    public Builder insecure(boolean disableChecks) {
      if (disableChecks) {
        trustAllHostnames(true);
        trustAllCertificates(true);
      }
      return this;
    }

    /**
     * Disable SSL hostname verification.
     * @param disableChecks
     * @return
     */
    public Builder trustAllHostnames(boolean disableChecks) {
      instance.trustAllHostnames = disableChecks;
      if (disableChecks) {
        HttpsURLConnection.setDefaultHostnameVerifier(new AllValidatingHostnameVerifier());
      }
      return this;
    }

    /**
     * Disable SSL certificate verification.
     * @param disableChecks
     * @return
     */
    public Builder trustAllCertificates(boolean disableChecks) {
      instance.trustAllCerts = disableChecks;
      return this;
    }

    /**
     * How long to wait for a connection to the remote resource.
     * @param milliseconds
     * @return
     */
    public Builder connectTimeout(int milliseconds) {
      instance.connectTimeout = milliseconds;
      return this;
    }

    /**
     * How long to wait for a response from the remote resource.
     * @param milliseconds
     * @return
     */
    public Builder readTimeout(int milliseconds) {
      instance.readTimeout = milliseconds;
      return this;
    }

    /**
     * The URL to connect to.
     * @param url
     * @return
     */
    public Builder url(String url) {
      instance.url = url;
      return this;
    }

    /**
     * Get an instance of JCurl with options configured by the {@link #Builder()}.
     * @return
     */
    public JCurl build() {
      instance.expectedResponseSet.add(200);

      setSystemProperty("javax.net.ssl.keyStore", instance.keyStore);
      setSystemProperty("javax.net.ssl.keyStoreType", instance.storeType);
      setSystemProperty("javax.net.ssl.keyStorePassword", instance.storePass);
      setSystemProperty("javax.net.ssl.trustStore", instance.trustStore);
      setSystemProperty("javax.net.ssl.trustStoreType", instance.trustType);
      setSystemProperty("javax.net.ssl.trustStorePassword", instance.trustPass);
      setSystemProperty("http.proxyHost", instance.proxyHost);
      setSystemProperty("http.proxyPort", instance.proxyPort);
      setSystemProperty("https.proxyHost", instance.proxyHost);
      setSystemProperty("https.proxyPort", instance.proxyPort);
      setSystemProperty("https.nonProxyHosts", instance.nonProxyHosts);

      if (instance.verbosity >= 3) {
        System.setProperty("javax.net.debug", "ssl");
      }

      HttpsURLConnection.setDefaultSSLSocketFactory((SSLSocketFactory) SSLSocketFactory.getDefault());

      initSSLContext();

      return instance;
    }
    
    private void initSSLContext() {
      try {
        KeyManager[] keyManagers = null;
        TrustManager[] trustManagers = null;

        if (instance.keyStore != null) {
          try (InputStream fis = new FileInputStream(instance.keyStore)) {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            String ksType = (instance.storeType != null) ? instance.storeType : "pkcs12";
            KeyStore ks = KeyStore.getInstance(ksType);

            ks.load(fis, instance.storePass.toCharArray());
            kmf.init(ks, instance.storePass.toCharArray());
            keyManagers = kmf.getKeyManagers();
          } catch (IOException | CertificateException | KeyStoreException | UnrecoverableKeyException e) {
            instance.errStream.println("Failed to initialize keystore: " + e.getMessage());
          }
        }

        if (instance.trustAllCerts) {
          trustManagers = new TrustManager[] {new AllTrustingTrustManager(),};
        } else if (instance.trustStore != null) {
          try (InputStream fis = new FileInputStream(instance.trustStore)) {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            String tsType = (instance.trustType != null) ? instance.trustType : KeyStore.getDefaultType();
            KeyStore ts = KeyStore.getInstance(tsType);

            ts.load(fis, instance.trustPass.toCharArray());
            tmf.init(ts);
            trustManagers = tmf.getTrustManagers();
          } catch (IOException | CertificateException | KeyStoreException e) {
            instance.errStream.println("Failed to initialize truststore: " + e.getMessage());
          }
        }

        SSLContext context = SSLContext.getInstance("SSL");
        context.init(keyManagers, trustManagers, new SecureRandom());
        SSLContext.setDefault(context);
        HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
      } catch (NoSuchAlgorithmException | KeyManagementException e) {
        instance.errStream.println("Failed to initialize SSL context: " + e.getMessage());
      }
    }

    /**
     * Helper method to only set VM properties if explicitly defined in program arguments.
     * Avoids overwriting properties set by VM options (-Dx.y.z) by nulls
     * if the corresponding program arguments are not set.
     */
    private void setSystemProperty(String property, String value) {
      if (value != null) {
        System.setProperty(property, value);
      } else {
        System.clearProperty(property);
      }
    }
  }


  private static class ConfigParser {
    private String[] argv;
    private int argi = 0;
    private String url;

    private JCurl parseCommandLine(String[] args) throws MalformedURLException, NoSuchAlgorithmException,
        KeyManagementException, FileNotFoundException {
      this.argv = args;
      Builder builder = builder();

      if (argv.length == 0) {
        printUsage();
        System.exit(0);
      }

      String urlString = null;

      while (argi < argv.length) {
        switch (argv[argi]) {
          case "-K":
          case "-config":
            String config = getNextArg();
            return parseConfig(config);

          case "-d":
          case "-data":
            String payload = getNextArg();
            builder.data(payload);
            break;

          case "-t":
            String tagMapLabel = getNextArg();
            String tagMapNode = getNextArg();
            builder.extract(tagMapLabel, tagMapNode);
            break;

          case "-a":
            String tagListNode = getNextArg();
            builder.extract(tagListNode);
            break;

          case "-c":
          case "-extract-cookies":
            builder.extractCookies(true);
            break;

          case "-H":
          case "-header":
            String headerName = getNextArg();
            String headerValue = getNextArg();
            builder.header(headerName, headerValue);
            break;

          case "-b":
          case "-cookie":
            String cookieName = getNextArg();
            String cookieValue = getNextArg();
            builder.cookie(cookieName, cookieValue);
            break;

          case "-F":
          case "-form":
            String formName = getNextArg();
            String formValue = getNextArg();
            builder.form(formName, formValue);
            break;

          case "-q":
          case "-query":
            String paramName = getNextArg();
            String paramValue = getNextArg();
            builder.query(paramName, paramValue);
            break;

          case "-X":
          case "-request":
            String method = getNextArg().toUpperCase();
            builder.method(HttpMethod.valueOf(method));
            break;

          case "-post":
            builder.method(HttpMethod.POST);
            break;

          case "-v":
            builder.verbosity(1);
            break;

          case "-vv":
            builder.verbosity(2);
            break;

          case "-vvv":
            builder.verbosity(3);
            break;

          case "-http":
            int expectedStatus = getNextIntArg();
            builder.expect(expectedStatus);
            break;

          case "-x":
          case "-proxy":
            String proxyUrl = getNextArg();
            builder.proxy(proxyUrl);
            break;

          case "-noproxy":
            String nonProxyHosts = getNextArg();
            builder.nonProxyHosts(nonProxyHosts);
            break;

          case "-keystore":
            String keyStore = getNextArg();
            builder.keystore(keyStore);
            break;

          case "-storepass":
            String storePass = getNextArg();
            builder.storepass(storePass);
            break;

          case "-storetype":
            String storeType = getNextArg();
            builder.storetype(storeType);
            break;

          case "-truststore":
            String trustStore = getNextArg();
            builder.truststore(trustStore);
            break;

          case "-trustpass":
            String trustPass = getNextArg();
            builder.trustpass(trustPass);
            break;

          case "-trusttype":
            String trustType = getNextArg();
            builder.trusttype(trustType);
            break;

          case "-k":
          case "-insecure":
            builder.insecure(true);
            break;

          case "-no-verify-hostname":
            builder.trustAllHostnames(true);
            break;

          case "-no-check-certificate":
            builder.trustAllCertificates(true);
            break;

          case "-out":
            String outputFile = getNextArg();
            builder.output(new PrintStream(new File(outputFile)));
            break;

          case "-err":
            String errOutputFile = getNextArg();
            builder.error(new PrintStream(new File(errOutputFile)));
            break;

          case "-h":
          case "-help":
            String help = getOptionalArg();
            if (help == null) {
              printUsage();
            } else {
              printConfigSample();
            }
            System.exit(0);

          default:
            if (urlString == null) { urlString = argv[argi]; } else {
              System.err.println("Invalid additional parameter \"" + argv[argi] + "\"");
              System.err.println("Try 'jcurl -h' or 'jcurl -help' for more information.");
              System.exit(1);
            }
        }
        argi++;
      }

      if (urlString == null || urlString.equals("")) {
        System.err.println("A URL is required");
        System.err.println("Try 'jcurl -h' or 'jcurl -help' for more information.");
        System.exit(1);
      }

      url = urlString;
      return builder.build();
    }

    private String getOptionalArg() {
      if (argi < argv.length - 1) {
        return argv[++argi];
      }
      return null;
    }

    private String getNextArg() {
      if (argi >= argv.length - 1) {
        System.err.println(argv[argi] + " requires a parameter.");
        System.exit(1);
      }
      return argv[++argi];
    }

    private int getNextIntArg() {
      if (argi >= argv.length - 1) {
        System.err.println(argv[argi] + " requires a parameter.");
        System.exit(1);
      }
      String s = argv[++argi];
      int i = 0;

      try {
        i = Integer.parseInt(s);
      } catch (NumberFormatException e) {
        System.err.println(argv[argi] + " requires an integer parameter.");
        System.exit(1);
      }
      return i;
    }

    private JCurl parseConfig(String config) {

      try (FileInputStream input = new FileInputStream(config)) {
        Builder builder = builder();

        JsonNode properties = MAPPER.readTree(input);

        for (Iterator<Map.Entry<String, JsonNode>> it = properties.fields(); it.hasNext(); ) {
          Map.Entry<String, JsonNode> field = it.next();
          String key = field.getKey();
          JsonNode value = field.getValue();
          switch (key) {
            case "keystore":
              builder.keystore(value.asText());
              break;
            case "storepass":
              builder.storepass(value.asText());
              break;
            case "storetype":
              builder.storetype(value.asText());
              break;
            case "truststore":
              builder.truststore(value.asText());
              break;
            case "trustpass":
              builder.trustpass(value.asText());
              break;
            case "trusttype":
              builder.trusttype(value.asText());
              break;
            case "insecure":
              builder.insecure(value.asBoolean());
              break;
            case "no-verify-hostname":
              builder.trustAllHostnames(value.asBoolean());
              break;
            case "no-check-certificate":
              builder.trustAllCertificates(value.asBoolean());
              break;
            case "proxy":
              builder.proxy(value.asText());
              break;
            case "noproxy":
              builder.nonProxyHosts(value.asText());
              break;
            case "connect-timeout":
              builder.connectTimeout(value.asInt());
              break;
            case "read-timeout":
              builder.readTimeout(value.asInt());
              break;
            case "verbosity":
              builder.verbosity(value.asInt());
              break;
            case "extract":
              for (Iterator<Map.Entry<String, JsonNode>> eit = value.fields(); eit.hasNext(); ) {
                Map.Entry<String, JsonNode> extract = eit.next();
                builder.extract(extract.getKey(), extract.getValue().asText());
              }
              break;
            case "headers":
              for (Iterator<Map.Entry<String, JsonNode>> hit = value.fields(); hit.hasNext(); ) {
                Map.Entry<String, JsonNode> header = hit.next();
                builder.header(header.getKey(), header.getValue().asText());
              }
              break;
            case "cookies":
              for (Iterator<Map.Entry<String, JsonNode>> cit = value.fields(); cit.hasNext(); ) {
                Map.Entry<String, JsonNode> cookie = cit.next();
                builder.cookie(cookie.getKey(), cookie.getValue().asText());
              }
              break;
            case "method":
              builder.method(HttpMethod.valueOf(value.asText().toUpperCase()));
              break;
            case "data":
              builder.data(value.asText());
              break;
            case "form":
              for (Iterator<Map.Entry<String, JsonNode>> fit = value.fields(); fit.hasNext(); ) {
                Map.Entry<String, JsonNode> formField = fit.next();
                builder.form(formField.getKey(), formField.getValue().asText());
              }
              break;
            case "url":
              this.url = value.asText();
              break;
          }
        }

        return builder.build();

      } catch (IOException | ClassCastException | NumberFormatException | ArrayIndexOutOfBoundsException e) {
        System.err.println("Couldn't parse config file " + config + ": " + e.getMessage());
        System.exit(1);
        return null;
      }

    }

    private void printUsage() {
      System.out.format("JCurl: JSON-aware Java cURL%n%n");
      System.out.format("Usage: jcurl [options...] <URL>%n");
      System.out.format("Sets 'Content-Type: application/json' by default unless noted otherwise. "
          + "To change the request content type, use '-H Content-Type your/mimetype'.%n");
      System.out.format("%nSSL options:%n");
      printOption("-keystore", "The keystore containing the certificate to use for authentication.");
      printOption("-storepass", "The keystore password.");
      printOption("-storetype",
          "The keystore type. Supported values: jks, jceks, pkcs11, pkcs12, bks, dks, windows-my.");
      printOption("-truststore",
          "The truststore containing the server certificate. If unspecified, the default Java "
              + "truststore (cacerts) is used.");
      printOption("-trustpass", "The truststore password.");
      printOption("-trusttype", "The truststore type. See \"-storetype\" for supported values.");
      printOption("-k, -insecure", "Disable checks for an HTTPS request. "
          + "Combines -no-verify-hostname and -no-check-certificate.");
      printOption("-no-verify-hostname", "Disable SSL hostname verification.");
      printOption("-no-check-certificate", "Disable SSL certificate verification.");

      System.out.format("%nRequest options:%n");
      printOption("-H, -header KEY VALUE",
          "Send a custom header with the request. Example: -H Content-Type application/json.");
      printOption("-d, -data DATA",
          "Send a POST request with DATA as request body. Example: -data '{\"message\": \"Hello "
              + "world!\", \"format\": \"TEXT\"}'.");
      printOption("-q, -query KEY VALUE",
          "Set request query parameters as \"KEY=VALUE\" paris separated by \"&\". Can be specified multiple times.");
      printOption("-F, -form KEY VALUE",
          "Send a POST request with data as \"KEY=VALUE\" pairs corresponding to a HTML form. "
              + "To specify a file, precede the file name with \"@\" (example: -F "
              + "file @/my/test/file.txt). Can be specified multiple times. Sets 'Content-Type: multipart/form-data'.");
      printOption("-b, -cookie KEY VALUE",
          "Set cookies used by the request. Can be specified multiple times.");
      printOption("-c, -extract-cookies",
          "Extract cookies returned by the call and return as \"NAME=VALUE\". "
              + "If multiple cookies are returned, each is output on a new line.");
      printOption("-post",
          "Send a POST request without request body. If neither -post nor -data is specified, sends"
              + " a GET request.");
      printOption("-X, -request METHOD",
          "Set the HTTP METHOD for the request. Supported values: GET, POST, PUT, DELETE, HEAD, CONNECT, OPTIONS.");
      printOption("-http STATUS",
          "Add HTTP STATUS as an expected response code. By default only HTTP 200 is expected as "
              + "correct status.");

      System.out.format("%nConnection options:%n");
      printOption("-x, -proxy", "Proxy the request through the specified URL. "
          + "Applies to all protocols unless excluded with \"-noproxy\". Example: -proxy https://my.proxy.com:8080.");
      printOption("-noproxy", "Bypass the proxy set by -x for the specified list of |-separated hosts. "
          + "Supports wildcards. Example: -noproxy my.host.org|*.otherhost.net.");
      printOption("-connect-timeout", "How long to wait, in seconds, for a connection to the remote "
          + "resource. Defaults to infinity.");
      printOption("-read-timeout", "How long to wait, in seconds, for a response from the remote "
          + "resource. Defaults to infinity.");

      System.out.format("%nOutput options:%n");
      printOption("-t LABEL NODE",
          "Extract NODE from a JSON object returned by the call and return as \"LABEL=NODE\". "
              + "Use \".\" to navigate within the JSON tree. "
              + "Example: -t uid userSystemInfo.id (returns \"uid=12345\").");
      printOption("-a NODE",
          "Iterate over a JSON array of objects returned by the call content and extract the value of "
              + "NODE. See -t for more details.");
      printOption("-v", "Verbose output. Will display request and response details.");
      printOption("-vv", "Very verbose output. Will display certificate details.");
      printOption("-vvv", "Very very verbose output. Turns on SSL debugging.");

      System.out.format("%nGeneral options:%n");
      printOption("-K, -config", "Read request parameters from a JSON file. The format of the config file "
          + "is \"parameter\":\"value\"; multivalued paramters (\"headers\", \"form\", \"extract\") should be JSON "
          + "arrays. To display a sample config file, run jcurl -h config.");
      System.out.format("%n");
      printOption("-h, -help", "Display this usage text.");
    }

    private void printConfigSample() {
      System.out.format("{%n");
      System.out.format("    \"keystore\"  : \"user.p12\",%n");
      System.out.format("    \"storepass\" : \"changeit\",%n");
      System.out.format("    \"storetype\" : \"pkcs12\",%n");
      System.out.format("    \"truststore\": \"server.p12\",%n");
      System.out.format("    \"trustpass\" : \"changeit\",%n");
      System.out.format("    \"trusttype\" : \"pkcs12\",%n");
      System.out.format("    \"proxy\"     : \"https://proxy.example.com:443\",%n");
      System.out.format("    \"noproxy\"   : \"https://localhost.com:8443\",%n");
      System.out.format("    \"insecure\"  : false,%n");
      System.out.format("    \"no-check-certificate\": false,%n");
      System.out.format("    \"no-verify-hostname\"  : false,%n");
      System.out.format("    \"connect-timeout\"     : 10,%n");
      System.out.format("    \"read-timeout\"        : 10,%n");
      System.out.format("    \"headers\"   : {%n");
      System.out.format("      \"Content-Type\"   : \"application/json\",%n");
      System.out.format("      \"Accept-Charset\" : \"utf-8\"%n");
      System.out.format("    },%n");
      System.out.format("    \"method\"    : \"post\",%n");
      System.out.format("    \"data\"      : \"{\\\"message\\\":\\\"Ping\\\",\\\"format\\\":\\\"TEXT\\\"}\",%n");
      System.out.format("    \"form\"      : {%n");
      System.out.format("      \"file\" : \"@/my/test/file.txt\"%n");
      System.out.format("    },%n");
      System.out.format("    \"url\"       : \"https://localhost.com:8443\",%n");
      System.out.format("    \"verbosity\" : 1,%n");
      System.out.format("    \"extract\"   : {%n");
      System.out.format("      \"uid\"  : \"userSystemInfo.id\"%n");
      System.out.format("    }%n");
      System.out.format("}%n");
    }

    private void printOption(String option, String desc) {
      System.out.format("%-26s %s%n", option, desc);
    }
  }


  public class Response {
    private int responseCode;
    private long timeTaken;
    private String cipherSuite;
    private String output;
    private String responseContentType;
    private Certificate[] serverCertificates;
    private Certificate[] clientCertificates;
    private Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private Map<String, String> cookies = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private Map<String, String> tagMap = new HashMap<>();
    private List<String> tagList = new ArrayList<>();
    private JsonNode jsonNode;

    /**
     * Print response data and optional meta information. Unless a different configuration is specified with
     * JCurl.Builder, only prints response data. Response is interpreted as application/json by default; this
     * can be changed with -H Content-Type your/mimetype.
     */
    public void print() throws CertificateParsingException, IOException {

      if (verbosity >= 2) {
        printCertificateDetails();
      }

      if (verbosity >= 1) {
        errStream.println("* Time taken: " + timeTaken / 1000000 + " ms");
        printResponseDetails();
        errStream.println("<");
      }

      if (verbosity >= 1 || output != null) {
        printOutput();
      }

      if (!expectedResponseSet.contains(responseCode)) {
        outStream.println("httpStatus=" + responseCode);
        System.exit(1);
      }

      if (output != null) {
        if ("application/json".equalsIgnoreCase(contentType) && "application/json".equalsIgnoreCase(responseContentType)) {
          printResponseJson();
        } else {
          errStream.println(output);
        }
      }
    }

    private void printCertificateDetails() throws CertificateParsingException {

      try {
        errStream.println("* Cipher Suite       : " + cipherSuite);

        for (Certificate cert : serverCertificates) {
          errStream.println("* Cert Type          : " + cert.getType());

          if (cert instanceof X509Certificate) {
            X509Certificate x509Cert = (X509Certificate) cert;

            //                  *      Type          : "
            errStream.println("*      Issuer        : " + x509Cert.getIssuerDN());
            errStream.println("*      Subject       : " + x509Cert.getSubjectDN());

            //                  *      Type      : "
            errStream.println("*      Issuer ID     : " + x509Cert.getIssuerUniqueID());
            errStream.println("*      Sig Algorithm : " + x509Cert.getSigAlgName());
            errStream.println("*      Basic Const   : " + x509Cert.getBasicConstraints());
            errStream.println("*      Ext Key Usage : " + x509Cert.getExtendedKeyUsage());
            errStream.println("*      Not Before    : " + x509Cert.getNotBefore());
            errStream.println("*      Not After     : " + x509Cert.getNotAfter());
            errStream.println("*      Subject ID    : " + x509Cert.getSubjectUniqueID());

            Collection<List<?>> altNames = x509Cert.getSubjectAlternativeNames();

            if (altNames != null) {
              for (List<?> nameList : altNames) {
                for (Object name : nameList) {
                  errStream.println("*      Alt Name     : " + name);
                }
              }
            }
          }

          errStream.println("*      Hash Code     : " + cert.hashCode());
          errStream.println("*      PubKey Algo   : " + cert.getPublicKey().getAlgorithm());
          errStream.println("*      PubKey Format : " + cert.getPublicKey().getFormat());
          errStream.println("\n");
        }
      } catch (IllegalStateException ignored) {}
    }

    private void printResponseDetails() throws CertificateParsingException {

      errStream.println("* HTTP Response: " + responseCode);

      for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
        for (String v : entry.getValue()) {
          if (entry.getKey() == null) {
            errStream.println("< " + v);
          } else {
            errStream.println("< " + entry.getKey() + " : " + v);
          }
        }
      }
    }

    private void printOutput() throws IOException {
      boolean newline = true;
      int c;

      try (StringReader reader = new StringReader(output)) {
        while ((c = reader.read()) != -1) {
          if (verbosity >= 1) {
            if (newline) {
              outStream.print("< ");
              newline = false;
            }

            switch (c) {
              case '\n':
                newline = true;
                errStream.println();
                break;

              case '\r':
                errStream.print("\\r");
                break;

              case '\t':
                errStream.print("\\t");
                break;

              case '\b':
                errStream.print("\\b");
                break;

              default:
                errStream.write(c);
            }
          }

        }
        errStream.println();
        errStream.flush();

      }
    }

    private void printResponseJson() throws IOException {
      JsonNode jsonNode = getJsonNode();

      if (!tagMap.isEmpty()) {
        printTagMap();
      }

      if (!tagList.isEmpty()) {
        printTagList();
      }

      if (tagList.isEmpty() && tagMap.isEmpty()) {
        outStream.println(jsonNode.toString());
      }

      if (extractCookies) {
        printCookies();
      }
    }

    private void printTagMap() {
      for (Map.Entry<String, String> entry : tagMap.entrySet()) {
        String name = entry.getKey();
        String value = entry.getValue();

        outStream.print(" " + name + "=\"");
        if (value == null) { outStream.print("null"); } else {
          outStream.print(value.replaceAll("\"", "\\\\\""));
        }
        outStream.println("\"");
      }
      outStream.println();
    }


    private void printTagList() {
      for (String tag : tagList) {
        outStream.print(tag + " ");
      }
    }

    private void printCookies() throws IOException {
        for (Map.Entry<String, String> cookie : cookies.entrySet()) {
          outStream.println(cookie.getKey() + "=" + cookie.getValue());
        }
    }

    /**
     *
     * @return
     */
    public int getResponseCode() {
      return responseCode;
    }

    /**
     *
     * @return
     */
    public long getTimeTaken() {
      return timeTaken;
    }

    /**
     *
     * @return
     */
    public String getCipherSuite() {
      return cipherSuite;
    }

    /**
     *
     * @return
     */
    public Certificate[] getServerCertificates() {
      return serverCertificates;
    }

    /**
     *
     * @return
     */
    public Certificate[] getClientCertificates() {
      return clientCertificates;
    }

    /**
     *
     * @return
     */
    public Map<String, List<String>> getHeaders() {
      return headers;
    }

    /**
     *
     * @return
     */
    public List<String> getHeader(String name) {
      return headers.get(name);
    }

    /**
     *
     * @return
     */
    public Map<String, String> getCookies() {
      return cookies;
    }

    /**
     *
     * @return
     */
    public String getCookie(String name) {
      return cookies.get(name);
    }

    /**
     *
     * @return
     */
    public String getOutput() {
      return output;
    }

    /**
     *
     * @param key
     * @return
     */
    public String getTag(String key) {
      return tagMap.get(key);
    }

    /**
     * Return a copy of the map of all tags captured as a result
     * of a call to {@link Builder.extract(String,String)}
     * 
     * @return a copy of the map of named tags.
     */
    public Map<String, String> getTagMap()
    {
      return new HashMap<>(tagMap);
    }

    /**
     * Return a copy of the list of all tags captured as a result
     * of a call to {@link Builder.extract(String)}
     * 
     * @return a copy of the list of indexed tags.
     */
    public List<String> getTagList()
    {
      return new ArrayList<>(tagList);
    }

    /**
     *
     * @param index
     * @return
     */
    public String getTag(int index) {
      return tagList.get(index);
    }

    /**
     * Return the content type of the response.
     * 
     * @return The MIME type of the response.
     */
    public String getContentType() {
        return responseContentType;
    }

    /**
     * Return the parsed JSON response, if any.
     * @return A JsonNode representing the response or null.
     */
    public JsonNode getJsonNode() throws IOException {
      if (jsonNode == null) {
        jsonNode = MAPPER.readTree(output);
      }
      return jsonNode;
    }

  }


  /**
   * A HostnameVerifier which accepts all hostnames. Disables SSL hostname verification.
   */
  static class AllValidatingHostnameVerifier implements HostnameVerifier {
    @Override
    public boolean verify(String hostname, SSLSession sslSession) {
      return true;
    }
  }


  /**
   * A TrustManager which accepts all certificates. Disables SSL certificate verification.
   */
  static class AllTrustingTrustManager implements X509TrustManager {

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String type) throws CertificateException {

    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String type) throws CertificateException {
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[] {};
    }
  }

  /**
   * Perform a HTTP(s) request to the provided URL. Unless a different configuration is specified with JCurl.Builder,
   * performs a GET request with Content-Type: application/json, expecting a HTTP 200 response.
   * This method requires the URL to have been set with {@link JCurl.Builder.url()}.
   *
   * @return a {@link java.net.HttpURLConnection} object.
   * @throws java.io.IOException if any.
   */
  public HttpURLConnection connect() throws IOException {
    if (url == null || "".equals(url.trim())) {
      errStream.println("A URL is required");
      errStream.println("Try 'jcurl -h' or 'jcurl -help' for more information.");
      System.exit(1);
    }

    return connect(url);
  }

  /**
   * Perform a HTTP(s) request to the provided URL. Unless a different configuration is specified with JCurl.Builder,
   * performs a GET request with Content-Type: application/json, expecting a HTTP 200 response.
   *
   * @param url a {@link java.net.URL} object.
   * @return a {@link java.net.HttpURLConnection} object.
   * @throws java.io.IOException if any.
   */
  public HttpURLConnection connect(URL url) throws IOException {
    return connect(url.toString());
  }

  /**
   * <p>Connect to the provided URL.</p>
   *
   * @param urlString a {@link java.lang.String} object.
   * @return a {@link java.net.HttpURLConnection} object.
   * @throws java.io.IOException if any.
   */
  public HttpURLConnection connect(String urlString) throws IOException {
    this.url = urlString;

    String targetUrl = buildUrl();

    URLConnection rawCon = new URL(targetUrl).openConnection();

    if (!(rawCon instanceof HttpURLConnection)) {
      errStream.println("Only http(s) is supported. Connection is of type " + rawCon.getClass());
      System.exit(1);
    }

    HttpURLConnection con = (HttpURLConnection) rawCon;
    con.setConnectTimeout(connectTimeout);
    con.setReadTimeout(readTimeout);
    con.setRequestProperty("User-Agent", "JCurl");
    con.setRequestProperty("Content-Type", contentType);

    // Set headers
    for (Map.Entry<String, String> header : headerMap.entrySet()) {
      con.setRequestProperty(header.getKey(), header.getValue());
    }

    // Set cookies
    if (!cookieMap.isEmpty()) {
      StringBuilder cookieBuilder = new StringBuilder();
      Iterator<Map.Entry<String, String>> cookies = cookieMap.entrySet().iterator();
      while (cookies.hasNext()) {
        Map.Entry<String, String> cookie = cookies.next();
        cookieBuilder.append(cookie.getKey())
            .append("=")
            .append(cookie.getValue());
        if (cookies.hasNext()) {
          cookieBuilder.append("; ");
        }
      }
      con.setRequestProperty("Cookie", cookieBuilder.toString());
    }

    if (verbosity >= 1) {
      errStream.println(this.toString());

      for (Map.Entry<String, List<String>> entry : con.getRequestProperties().entrySet()) {
        for (String v : entry.getValue()) {
          if (entry.getKey() == null) {
            errStream.println("> " + v);
          } else {
            errStream.println("> " + entry.getKey() + ": " + v);
          }
        }
      }
      errStream.println(">");
    }

    switch (method) {
      case POST:
        con.setRequestMethod("POST");

        if (data != null) {
          con.setDoOutput(true);
          DataOutputStream wr = new DataOutputStream(con.getOutputStream());

          wr.writeBytes(data);

          if (verbosity >= 1) {
            errStream.print("> ");
            errStream.println(data);
          }

          wr.flush();
          wr.close();
        }

        if (!formMap.isEmpty()) {
          MultipartUtility multipart = new MultipartUtility(con);

          for (Map.Entry<String, String> field : formMap.entrySet()) {
            String key = field.getKey();
            String value = field.getValue();
            if (value.startsWith("@")) {  //handle file
              multipart.addFilePart(key, new File(value.substring(1)));
            } else {                      //handle form param
              multipart.addFormField(key, value);
            }

          }
          multipart.finish();
        }
        break;
      default:
        con.setRequestMethod(method.name());
        break;
    }

    return con;
  }

  /**
   * Process response data and, if applicable, HTTPS information. The {@link org.symphonyoss.symphony.jcurl.JCurl.Response} object returned can be printed
   * out with response.print().
   *
   * @param con a {@link java.net.HttpURLConnection} object.
   * @return a {@link org.symphonyoss.symphony.jcurl.JCurl.Response} object.
   * @throws java.io.IOException if any.
   * @throws java.security.cert.CertificateParsingException if any.
   */
  public Response processResponse(HttpURLConnection con) throws IOException, CertificateParsingException {
    Response response = new Response();

    long startTime = System.nanoTime();
    con.connect();
    long endTime = System.nanoTime();

    response.timeTaken = endTime - startTime;

    processResponseHeaders(con, response);
    processResponseCode(con, response);
    processResponseCertificates(con, response);
    processResponseOutput(con, response);
    processResponseTags(response);

    return response;
  }

  @Override
  public String toString() {
    StringBuilder output = new StringBuilder();

    output.append("java -jar jcurl.jar ");

    if (keyStore != null) {
      output.append(String.format("-keystore %s ", keyStore));
    }

    if (storePass != null) {
      output.append(String.format("-storepass %s ", storePass));
    }

    if (storeType != null) {
      output.append(String.format("-storetype %s ", storeType));
    }

    if (trustStore != null) {
      output.append(String.format("-truststore %s ", trustStore));
    }

    if (trustPass != null) {
      output.append(String.format("-trustpass %s ", trustPass));
    }

    if (trustType != null) {
      output.append(String.format("-trusttype %s ", trustType));
    }

    for (Map.Entry<String, String> header : headerMap.entrySet()) {
      output.append(String.format("-H %s %s ", header.getKey(), header.getValue()));
    }

    for (Map.Entry<String, String> cookie : cookieMap.entrySet()) {
      output.append(String.format("-b %s %s ", cookie.getKey(), cookie.getValue()));
    }

    for (Map.Entry<String, String> formParam : formMap.entrySet()) {
      output.append(String.format("-F %s %s ", formParam.getKey(), formParam.getValue()));
    }

    for (Map.Entry<String, String> tag : tagMap.entrySet()) {
      output.append(String.format("-t %s %s ", tag.getKey(), tag.getValue()));
    }

    for (String tag : tagList) {
      output.append(String.format("-a %s ", tag));
    }

    if (extractCookies) {
      output.append("-c ");
    }

    for (Integer status : expectedResponseSet) {
      if (status != 200) {
        output.append(String.format("-http %s ", status));
      }
    }

    if (proxyHost != null) {
      output.append(String.format("-x %s:%s ", proxyHost, proxyPort));
    }

    if (nonProxyHosts != null) {
      output.append(String.format("-noproxy %s ", nonProxyHosts));
    }

    if (trustAllHostnames) {
      output.append("-no-verify-hostname ");
    }

    if (trustAllCerts) {
      output.append("-no-check-certificate ");
    }

    if (verbosity > 0) {
      output.append(String.format("-%0" + verbosity + "d ", 0).replace("0", "v"));
    }

    if (data != null) {
      output.append(String.format("-data %s ", data));
    } else if (method == HttpMethod.POST) {
      output.append("-post ");
    } else {
      output.append(String.format("-X %s ", method.name()));
    }

    output.append(buildUrl());

    return output.toString();
  }

  private void processResponseHeaders(HttpURLConnection con, Response response) throws IOException {
    for (Map.Entry<String, List<String>> header : con.getHeaderFields().entrySet()) {
      String headerName = header.getKey();
      List<String> headerValue = header.getValue();

      if (headerName != null && headerValue != null) {

        if ("Content-Type".equalsIgnoreCase(headerName)) {
          String contentType = headerValue.get(0);
          if (contentType != null) {
            response.responseContentType = contentType.split(";")[0];
          }
        } else if ("Set-Cookie".equalsIgnoreCase(headerName)) {
          for (String cookie : headerValue) {
            String[] cookieValues = cookie.split(";\\s*");

            if (cookieValues.length > 0) {
              String[] cookieKV = cookieValues[0].split("=");

              if (cookieKV.length == 2) {
                response.cookies.put(cookieKV[0], cookieKV[1]);
              }
            }
          }
        } else {
          response.headers.put(headerName, headerValue);
        }
      }
    }
  }

  private void processResponseCode(HttpURLConnection con, Response response) throws IOException {
    try {
      response.responseCode = con.getResponseCode();
    } catch (FileNotFoundException e) {
      response.responseCode = 404;
    }
  }

  private void processResponseCertificates(HttpURLConnection con, Response response) throws SSLPeerUnverifiedException {
    if (con instanceof HttpsURLConnection) {
      try {
        HttpsURLConnection secureConn = (HttpsURLConnection) con;
        response.cipherSuite = secureConn.getCipherSuite();
        response.serverCertificates = secureConn.getServerCertificates();
        response.clientCertificates = secureConn.getLocalCertificates();
      } catch (IllegalStateException e) {
        // If the response is not a 200, getting response certificates will fail with the (misleading) message
        // "connection not yet open". Ignore this.
      }
    }
  }

  private void processResponseOutput(HttpURLConnection con, Response response) throws IOException {
    InputStream in = con.getErrorStream();
    try {
      if (in == null) {
        in = con.getInputStream();
      }
      ByteArrayOutputStream result = new ByteArrayOutputStream();
      byte[] buffer = new byte[1024];
      int length;
      while ((length = in.read(buffer)) != -1) {
        result.write(buffer, 0, length);
      }
      response.output = result.toString();
    } finally {
      if (in != null) {
        in.close();
      }
    }
  }

  private void processResponseTags(Response response)  {
    // Only extract tags if the content type is JSON and the output is not blank
    if (response.output != null && ! "".equals(response.output.trim())
        && "application/json".equalsIgnoreCase(this.contentType)
        && "application/json".equalsIgnoreCase(response.responseContentType)) {

      JsonNode responseJson;
      try {
        responseJson = response.getJsonNode();
      } catch (IOException e) {
        // If the response JSON is malformed, stop processing
        return;
      }

      if (responseJson == null) {
        return;
      }

      for (Map.Entry<String, String> entry : tagMap.entrySet()) {
        String name = entry.getKey();
        String tag = entry.getValue();
        JsonNode value = responseJson;

        for (String part : tag.split("\\.")) {
          value = value.get(part);
          if (value == null) {
            break;
          }
        }
        response.tagMap.put(name, (value != null) ? value.asText() : null);
      }

      for (JsonNode childNode : responseJson) {
        for (String tag : tagList) {
          JsonNode value = childNode;

          for (String part : tag.split("\\.")) {
            value = value.get(part);
            if (value == null) {
              break;
            }
          }

          if (value != null) {
            response.tagList.add(value.asText());
          }
        }
      }
    }
  }

  private String buildUrl() {
    if (queryMap == null || queryMap.isEmpty()) {
      return url;
    }

    StringBuilder urlBuilder = new StringBuilder(url);

    String[] urlParts = url.split("/");

    if (urlParts[urlParts.length-1].contains("?")) {
      urlBuilder.append("&");
    } else {
      urlBuilder.append("?");
    }

    Iterator<Map.Entry<String, String>> it = queryMap.entrySet().iterator();
    while (it.hasNext()) {
      Map.Entry<String, String> queryParam = it.next();
      urlBuilder.append(String.format("%s=%s", queryParam.getKey(), queryParam.getValue()));

      if (it.hasNext()) {
        urlBuilder.append("&");
      }
    }

    return urlBuilder.toString();
  }

  public String getUrl() {
    return url;
  }

  public String getData() {
    return data;
  }

  public String getKeyStore() {
    return keyStore;
  }

  public String getStoreType() {
    return storeType;
  }

  public String getStorePass() {
    return storePass;
  }

  public String getTrustStore() {
    return trustStore;
  }

  public String getTrustType() {
    return trustType;
  }

  public String getTrustPass() {
    return trustPass;
  }

  public String getProxyHost() {
    return proxyHost;
  }

  public String getProxyPort() {
    return proxyPort;
  }

  public String getNonProxyHosts() {
    return nonProxyHosts;
  }

  public int getVerbosity() {
    return verbosity;
  }

  public int getConnectTimeout() {
    return connectTimeout;
  }

  public int getReadTimeout() {
    return readTimeout;
  }

  public boolean isTrustAllHostnames() {
    return trustAllHostnames;
  }

  public boolean isTrustAllCerts() {
    return trustAllCerts;
  }

  public boolean isExtractCookies() {
    return extractCookies;
  }

  public List<String> getTagList() {
    return tagList;
  }

  public Map<String, String> getTagMap() {
    return tagMap;
  }

  public Map<String, String> getFormMap() {
    return formMap;
  }

  public Map<String, String> getHeaderMap() {
    return headerMap;
  }

  public Map<String, String> getQueryMap() {
    return queryMap;
  }

  public Map<String, String> getCookieMap() {
    return cookieMap;
  }

  public Set<Integer> getExpectedResponseSet() {
    return expectedResponseSet;
  }

  public HttpMethod getMethod() {
    return method;
  }

  public String getContentType() {
    return contentType;
  }

}
