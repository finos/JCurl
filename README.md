[![Licence](https://img.shields.io/badge/licence-Apache%20Licence%20%282.0%29-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Maven Central](https://img.shields.io/maven-central/v/org.symphonyoss.symphony/jcurl.svg)](http://repo1.maven.org/maven2/org/symphonyoss/symphony/jcurl/)
[![FINOS - Active](https://cdn.jsdelivr.net/gh/finos/contrib-toolbox@master/images/badge-active.svg)](https://finosfoundation.atlassian.net/wiki/display/FINOS/Active)

# JCurl
JSON-aware curl (1) in Java

```
Usage: jcurl [options...] <URL>
Sets 'Content-Type: application/json' by default unless noted otherwise. To change the request content type, use '-H Content-Type your/mimetype'.

SSL options:
-keystore                  The keystore containing the certificate to use for authentication.
-storepass                 The keystore password.
-storetype                 The keystore type. Supported values: jks, jceks, pkcs11, pkcs12, bks, dks, windows-my.
-truststore                The truststore containing the server certificate. If unspecified, the default Java truststore (cacerts) is used.
-trustpass                 The truststore password.
-trusttype                 The truststore type. See "-storetype" for supported values.
-k, -insecure              Disable checks for an HTTPS request. Combines -no-verify-hostname and -no-check-certificate.
-no-verify-hostname        Disable SSL hostname verification.
-no-check-certificate      Disable SSL certificate verification.

Request options:
-H, -header KEY VALUE      Send a custom header with the request. Example: -H Content-Type application/json.
-d, -data DATA             Send a POST request with DATA as request body. Example: -data '{"message": "Hello world!", "format": "TEXT"}'.
-q, -query KEY VALUE       Set request query parameters as "KEY=VALUE" paris separated by "&". Can be specified multiple times.
-F, -form KEY VALUE        Send a POST request with data as "KEY=VALUE" pairs corresponding to a HTML form. To specify a file, precede the file name with "@" (example: -F file @/my/test/file.txt). Can be specified multiple times. Sets 'Content-Type: multipart/form-data'.
-b, -cookie KEY VALUE      Set cookies used by the request. Can be specified multiple times.
-c, -extract-cookies       Extract cookies returned by the call and return as "NAME=VALUE". If multiple cookies are returned, each is output on a new line.
-post                      Send a POST request without request body. If neither -post nor -data is specified, sends a GET request.
-X, -request METHOD        Set the HTTP METHOD for the request. Supported values: GET, POST, PUT, DELETE, HEAD, CONNECT, OPTIONS.
-http STATUS               Add HTTP STATUS as an expected response code. By default only HTTP 200 is expected as correct status.

Connection options:
-x, -proxy                 Proxy the request through the specified URL. Applies to all protocols unless excluded with "-noproxy". Example: -proxy https://my.proxy.com:8080.
-noproxy                   Bypass the proxy set by -x for the specified list of |-separated hosts. Supports wildcards. Example: -noproxy my.host.org|*.otherhost.net.
-connect-timeout           How long to wait, in seconds, for a connection to the remote resource. Defaults to infinity.
-read-timeout              How long to wait, in seconds, for a response from the remote resource. Defaults to infinity.

Output options:
-t LABEL NODE              Extract NODE from a JSON object returned by the call and return as "LABEL=NODE". Use "." to navigate within the JSON tree. Example: -t uid userSystemInfo.id (returns "uid=12345").
-a NODE                    Iterate over a JSON array of objects returned by the call content and extract the value of NODE. See -t for more details.
-v                         Verbose output. Will display request and response details.
-vv                        Very verbose output. Will display certificate details.
-vvv                       Very very verbose output. Turns on SSL debugging.

General options:
-K, -config                Read request parameters from a JSON file. The format of the config file is "parameter":"value"; multivalued paramters ("headers", "form", "extract") should be JSON arrays. To display a sample config file, run jcurl -h config.

-h, -help                  Display this usage text.
```

Sample config file:

```javascript

{
    "keystore"  : "user.p12",
    "storepass" : "changeit",
    "storetype" : "pkcs12",
    "truststore": "server.p12",
    "trustpass" : "changeit",
    "trusttype" : "pkcs12",
    "proxy"     : "https://proxy.example.com:443",
    "noproxy"   : "https://localhost.com:8443",
    "insecure"  : false,
    "no-check-certificate": false,
    "no-verify-hostname"  : false,
    "connect-timeout"     : 10,
    "read-timeout"        : 10,
    "headers"   : {
      "Content-Type"   : "application/json",
      "Accept-Charset" : "utf-8"
    },
    "cookies"   : {
      "JSESSIONID":     : "abcd1234"  
    },
    "method"    : "post",
    "data"      : "{\"message\":\"Ping\",\"format\":\"TEXT\"}",
    "form"      : {
      "file" : "@/my/test/file.txt"
    },
    "url"       : "https://localhost.com:8443",
    "verbosity" : 1,
    "extract"   : {
      "uid"  : "userSystemInfo.id"
    }
}
```

Script usage:

```bash
#!/usr/bin/env bash
 
# Get a session token.
# Extract the JSON node "token" and save the value as $skey.
eval `java -jar jcurl.jar -keystore bot.user1.p12 -storetype pkcs12 -storepass changeit -t skey token -v -post https://localhost.symphony.com:8444/sessionauth/v1/authenticate`
# Response: {"name":"sessionToken","token":"1298eb1ef8999fb82d03b9e0936a1820744a532705baf5b254702842de67f0ec2d80f3b88d8651d3c443fa4b99d9c06fd75731b2bdae362a6f03dc0ef347002a"}
 
# Get a KM token.
# Extract the JSON node "token" and save the value as $kmkey.
eval `java -jar jcurl.jar -keystore bot.user1.p12 -storetype pkcs12 -storepass changeit -t kmkey token -v -post https://localhost.symphony.com:8444/keyauth/v1/authenticate`
# Response: {"name":"keyManagerToken","token":"0100ce5146fb49fa1392a40c9e13f14afb4ac169c021e6fd4571e4ac9140e5816e5d45e892e4deb2f73d5608327665f5c21c96afb5fdd1aa993d6972aac5df134afa0069e6dc5aa87236685444390c4e77ea012fa72ad0ff6f943b4bf1b406130ab6a8337336c80b0f4deed29a4aaa93653e80cf52193d6e1a7b40e4ecb07b0d94899c3999e631dfe98242502426c15944d91946304157773ded85131aced6502f79e0e1465fe46d67a1364c0e083cae51b99bca1b6a333259944c0109b8"}
 
# Create a user.
# Extract the JSON node "userSystemInfo.id" and save the value as $uid.
eval `java -jar jcurl.jar -t uid userSystemInfo.id -H sessionToken $skey -H Content-Type application/json -v -data '{"userAttributes": {"accountType": "NORMAL","emailAddress": "bot.user99@localhost.com","firstName": "Local","lastName": "Bot99","userName": "bot.user10","displayName": "Local Bot99"},"password": {"hSalt": "KG4bjfspZAVE/9cxAm6gow==","hPassword": "74woSu42oR/w2jhhAPMWdLVBtMnOqTbyx+CRuzkhjGg=","khSalt": "KG4bjfspZAVE/9cxAm6gow==","khPassword": "74woSu42oR/w2jhhAPMWdLVBtMnOqTbyx+CRuzkhjGg="}, "roles": ["INDIVIDUAL"]}' https://localhost.symphony.com:8446/pod/v1/admin/user/create`
# Response: {"userAttributes":{"emailAddress":"bot.user99@localhost.com","firstName":"Local","lastName":"Bot99","userName":"bot.user99","displayName":"Local Bot99","accountType":"NORMAL"},"userSystemInfo":{"id":68719476761,"status":"ENABLED","createdDate":1480645365000,"createdBy":"68719476740","lastUpdatedDate":1480645365540},"roles":["INDIVIDUAL"]}
 
# Create a room.
# Extract the JSON node "roomSystemInfo.id" and save the value as $sid.
eval `java -jar jcurl.jar -t sid roomSystemInfo.id -H sessionToken $skey -H Content-Type application/json -v -data '{"name":"Test room","description":"Room for testing","membersCanInvite":"true","discoverable":"true","public":"true","readOnly":"false","copyProtected":"false"}' https://localhost.symphony.com:8446/pod/v2/room/create`
# Response: {"roomAttributes":{"name":"Test room","description":"Room for testing","membersCanInvite":true,"discoverable":true,"readOnly":false,"copyProtected":false,"public":true},"roomSystemInfo":{"id":"bDF-x322YHs_QuLhGBUjtn___qdCqKffdA","creationDate":1480645367861,"createdByUserId":68719476743,"active":true}}
 
# Add user to room
java -jar jcurl.jar -H sessionToken $skey -H Content-Type application/json -v -data '{"id":'$uid'}' https://localhost.symphony.com:8446/pod/v1/room/$sid/membership/add
# Response: {"format":"TEXT","message":"Member added"}
 
# Send a test message
java -jar jcurl.jar -H sessionToken $skey -H keyManagerToken $kmkey -H Content-Type application/json -v -data '{"message":"Hello world!", "format":"TEXT"}' https://localhost.symphony.com:8446/agent/v2/stream/$sid/message/create
# Response: {"id":"61YWWE7UReiUoW6HRtWMQH___qdCqJYadA","timestamp":"1480645372422","v2messageType":"V2Message","streamId":"bDF-x322YHs_QuLhGBUjtn___qdCqKffdA","attachments":[],"fromUserId":68719476743,"message":"Hello world!"}
```

Programmatic usage:

```java
//Get a session token

JCurl jcurl = JCurl.builder()
    .method(JCurl.HttpMethod.POST)
    .keystore("bot.user1.p12")      //Set user certificate for authentication
    .storepass("changeit")
    .storetype("pkcs12")
    .extract("skey", "token")       //Extract the value of the JSON tag "token" to a map entry under "skey"  
    .build();

HttpURLConnection connection = jcurl.connect("https://localhost.symphony.com:8444/sessionauth/v1/authenticate");
JCurl.Response response = jcurl.processResponse(connection);
String sessionToken = response.getTag("skey");  //Retrieve the extracted tag saved as "skey"

//Get session info (returns the requesting user ID)

jcurl = JCurl.builder()
    .method(JCurl.HttpMethod.GET)               //HTTP GET is the default; this line can be skipped
    .header("sessionToken", sessionToken)       //Set the session token in the request header
    .extract("uid", "userId")                   //Extract the user ID from the response as "uid"
    .build();

connection = jcurl.connect("https://localhost.symphony.com:8443/pod/v1/sessioninfo");
response = jcurl.processResponse(connection);
String userId = response.getTag("uid");

System.out.println("User ID: " + userId);

//Create an IM with user 123456

jcurl = JCurl.builder()
    .method(JCurl.HttpMethod.POST)              //Set implicitly by specifying ".data()"; this line can be skipped
    .header("sessionToken", sessionToken)       //Set the session token in the request header
    .data("[123456]")                           //Set the JSON payload of the request
    .extract("sid", "id")                       //Extract the stream ID of the conversation as "sid"
    .build();

connection = jcurl.connect("https://localhost.symphony.com:8443/pod/v1/im/create");
response = jcurl.processResponse(connection);
String streamId = response.getTag("sid");

System.out.println("Stream ID: " + streamId);

//Print the output of the call
System.out.println(response.getOutput());       //Prints '{"id": "wFwupr-KY3QW1oEkjE61x3___qsvcXdFdA"}'
```

## Contributing

1. Fork it (<https://github.com/symphonyoss/JCurl/fork>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Read our [contribution guidelines](.github/CONTRIBUTING.md) and [Community Code of Conduct](https://www.finos.org/code-of-conduct)
4. Commit your changes (`git commit -am 'Add some fooBar'`)
5. Push to the branch (`git push origin feature/fooBar`)
6. Create a new Pull Request

## License

The code in this repository is distributed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).

Copyright 2016-2019 Symphony LLC