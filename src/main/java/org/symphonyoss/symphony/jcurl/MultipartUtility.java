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

import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URLConnection;
import java.nio.file.Files;
import java.util.UUID;

/**
 * This class contains helper methods for multipart/form-data support in {@link HttpURLConnection} connections.
 *
 * @author ldrozdz
 */
class MultipartUtility {
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
  MultipartUtility(HttpURLConnection httpConn)
      throws IOException {
    this.httpConn = httpConn;
    this.httpConn.setDoOutput(true);
    this.boundary = buildBoundary();
    this.httpConn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + this.boundary);
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
   * @param name - name of the header field
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
  void addFormField(String name, String value) throws IOException {
    writer.writeBytes("--" + boundary + LINE_FEED);
    writer.writeBytes("Content-Disposition: form-data; name=\"" + name + "\"" + LINE_FEED);
    writer.writeBytes("Content-Type: text/plain; charset=" + charset + LINE_FEED);
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
  void addFilePart(String fieldName, File uploadFile)
      throws IOException {
    String fileName = uploadFile.getName();
    writer.writeBytes("--" + boundary + LINE_FEED);
    writer.writeBytes("Content-Disposition: form-data; name=\"" + fieldName + "\"; filename=\"" + fileName + "\"" + LINE_FEED);
    writer.writeBytes("Content-Type: " + URLConnection.guessContentTypeFromName(fileName) + LINE_FEED);
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
  void finish() throws IOException {
    writer.writeBytes(LINE_FEED);
    writer.flush();
    writer.writeBytes("--" + boundary + "--" + LINE_FEED);
    writer.close();
  }
}
