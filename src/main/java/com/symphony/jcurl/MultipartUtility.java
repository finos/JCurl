package com.symphony.jcurl;

import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URLConnection;
import java.nio.file.Files;
import java.util.UUID;

/**
 * Created by Łukasz Dróżdż on 29/04/16.
 *
 * Adapted from http://stackoverflow.com/a/34409142
 */
public class MultipartUtility {
  private final String boundary;
  private static final String LINE_FEED = "\r\n";
  private String charset = "utf-8";
  private OutputStream outputStream;
  private DataOutputStream writer;
  private HttpURLConnection httpConn;

  /**
   * This constructor initializes a new HTTP POST request with content type
   * is set to multipart/form-data
   * @param httpConn
   * @throws IOException
   */
  public MultipartUtility(HttpURLConnection httpConn)
      throws IOException {
    this.httpConn = httpConn;
    this.httpConn.setDoOutput(true);
    this.boundary = buildBoundary();
    this.httpConn.setRequestProperty("Content-Type",
        "multipart/form-data; boundary=" + this.boundary);
    this.outputStream = httpConn.getOutputStream();
    this.writer = new DataOutputStream(this.outputStream);
  }

  private String buildBoundary() {
    StringBuilder sb = new StringBuilder(64);
    sb.append("----MultipartBoundary----");
    sb.append(UUID.randomUUID());
    sb.append("--");
    return sb.toString();
  }

  /**
   * Adds a header field to the request.
   *
   * @param name  - name of the header field
   * @param value - value of the header field
   */
  public void addHeaderField(String name, String value) throws IOException {
    writer.writeBytes(name + ": " + value + LINE_FEED);
    writer.flush();
  }

  /**
   * Adds a form field to the request
   * @param name field name
   * @param value field value
   */
  public void addFormField(String name, String value) throws IOException {
    writer.writeBytes("--" + boundary + LINE_FEED);
    writer.writeBytes("Content-Disposition: form-data; name=\"" + name + "\"" + LINE_FEED);
    writer.writeBytes("Content-Type: text/plain; charset=" + charset +
        LINE_FEED);
    writer.writeBytes(LINE_FEED);
    writer.writeBytes(value + LINE_FEED);
    writer.flush();
  }

  /**
   * Adds a upload file section to the request
   * @param fieldName name attribute in <input type="file" name="..." />
   * @param uploadFile a File to be uploaded
   * @throws IOException
   */
  public void addFilePart(String fieldName, File uploadFile)
      throws IOException {
    String fileName = uploadFile.getName();
    writer.writeBytes("--" + boundary + LINE_FEED);
    writer.writeBytes(
        "Content-Disposition: form-data; name=\"" + fieldName
            + "\"; filename=\"" + fileName + "\"" + LINE_FEED);
    writer.writeBytes(
        "Content-Type: "
            + URLConnection.guessContentTypeFromName(fileName) + LINE_FEED);
    writer.writeBytes("Content-Transfer-Encoding: binary" + LINE_FEED);
    writer.writeBytes(LINE_FEED);
    writer.flush();

    byte[] uploadData = Files.readAllBytes(uploadFile.toPath());
    writer.write(uploadData);
    writer.writeBytes(LINE_FEED);
    outputStream.flush();
    writer.flush();
  }

  /**
   * Completes the request.
   * @return a list of Strings as response in case the server returned
   * status OK, otherwise an exception is thrown.
   * @throws IOException
   */
  public void finish() throws IOException {
    writer.writeBytes(LINE_FEED);
    writer.flush();
    writer.writeBytes("--" + boundary + "--" + LINE_FEED);
    writer.close();
  }
}
