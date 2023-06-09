/*******************************************************************************
 * <pre>
 *  Imixs Workflow 
 *  Copyright (C) 2001, 2011 Imixs Software Solutions GmbH,  
 *  http://www.imixs.com
 *  
 *  This program is free software; you can redistribute it and/or 
 *  modify it under the terms of the GNU General Public License 
 *  as published by the Free Software Foundation; either version 2 
 *  of the License, or (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful, 
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 *  General Public License for more details.
 *  
 *  You can receive a copy of the GNU General Public
 *  License at http://www.gnu.org/licenses/gpl.html
 *  
 *  Project: 
 *      http://www.imixs.org
 *      http://java.net/projects/imixs-workflow
 *  
 *  Contributors:  
 *      Imixs Software Solutions GmbH - initial API and implementation
 *      Ralph Soika - Software Developer
 * </pre>
 *******************************************************************************/

package org.imixs.jwt;

import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import javax.crypto.SecretKey;
import jakarta.json.Json;
import jakarta.json.JsonNumber;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;

/**
 * The JWTBuilder can be used to construct a JSON Web Token. The Builder expects a valid SecrectKey
 * to sign the token.
 * 
 * @author rsoika
 *
 */
public class JWTBuilder {

  SecretKey key;
  String header;
  String payload;
  String signature;
  Map<String, String> claims;

  public static String DEFAULT_HEADER = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

  public JWTBuilder setKey(SecretKey key) {
    this.key = key;
    return this;
  }

  /**
   * Set a JSON header. The header will be base64 encoded.
   * 
   * @param header
   * @return
   */
  public JWTBuilder setHeader(String header) {
    this.header = HMAC.encodeBase64(header.getBytes());
    return this;
  }

  /**
   * Set a JSON payload. The payload will be base64 encoded.
   * 
   * @param encodedHeader
   * @return
   */
  public JWTBuilder setPayload(String payload) {

    // verify if 'iat' is included
    if (payload != null) {
      // insert IAT....
      long iat = 0;

      JsonReader reader = Json.createReader(new StringReader(payload));
      JsonObject payloadObject = reader.readObject();
      try {
        // test issue date
        JsonNumber jsonnumber = payloadObject.getJsonNumber("iat");
        iat = jsonnumber.longValue();
      } catch (NullPointerException | ClassCastException e) {
        iat = -1;
      }
      if (iat <= 0) {
        // does not exist - so we add it
        String iatVal = "\"iat\":" + ((new Date().getTime()) / 1000) + "";
        payload = "{" + iatVal + "," + payload.substring(payload.indexOf("{") + 1);
      }

    }

    this.payload = HMAC.encodeBase64(payload.getBytes());
    return this;
  }

  public JWTBuilder setClaim(String claim, String value) {
    if (claims == null) {
      claims = new HashMap<String, String>();
    }
    claims.put(claim, value);
    return this;
  }

  /**
   * Builds the payload with all claims
   * 
   * @return
   */
  @SuppressWarnings("rawtypes")
  public JWTBuilder build() {
    if (claims == null) {
      claims = new HashMap<String, String>();
    }
    if (!claims.containsKey("iat")) {
      // iat does not exist - so we add it
      claims.put("iat", "" + ((new Date().getTime()) / 1000));
    }

    payload = "{";
    Iterator<Entry<String, String>> it = claims.entrySet().iterator();
    while (it.hasNext()) {
      Map.Entry pair = (Map.Entry) it.next();
      payload = payload + "\"" + pair.getKey() + "\":\"" + pair.getValue() + "\",";
      it.remove(); // avoids a ConcurrentModificationException
    }
    // remove last ,
    payload = payload.substring(0, payload.length() - 1) + "}";

    this.payload = HMAC.encodeBase64(payload.getBytes());

    return this;
  }

  /**
   * Set an base64 encoded header
   * 
   * @param header
   * @return
   */
  public JWTBuilder setEncodedHeader(String header) {
    this.header = header;
    return this;
  }

  /**
   * Set the base64 encoded payload
   * 
   * @param encodedHeader
   * @return
   */
  public JWTBuilder setEncodedPayload(String payload) {
    this.payload = payload;
    return this;
  }

  /**
   * Signs the header+payload
   * 
   * @return
   * @throws InvalidKeyException
   * @throws NoSuchAlgorithmException
   */
  public JWTBuilder sign() throws JWTException {
    String message = header + "." + payload;
    byte[] bSignature;
    try {
      bSignature = HMAC.createSignature(key, message.getBytes());
    } catch (InvalidKeyException e) {
      throw new JWTException("INVALID_KEY", "Invalid key!", e);

    } catch (NoSuchAlgorithmException e) {
      throw new JWTException("INVALID_ALGORITHM", "Invalid algorithm!", e);
    }

    signature = HMAC.encodeBase64(bSignature);

    return this;

  }

  /**
   * Returns the base64 encoded signature
   * 
   * @return
   */
  public String getSignature() {
    return signature;
  }

  /**
   * Returns the JSON Web Token. At a minimum the Key and payload must be set before. If no header
   * was set, the header is created based on the Key. If no signature was generated, the signature
   * will be added.
   * 
   * @return
   * @throws JWTException
   */
  public String getToken() throws JWTException {
    if (key == null) {
      throw new JWTException("MISSING_SECRET_KEY", "No SecretKey defined!");
    }

    if (payload == null || payload.isEmpty()) {
      throw new JWTException("MISSING_PAYLOAD", "No Payload defined!");
    }

    if (header == null) {
      // create default header
      setHeader("{\"alg\":\"" + JWSAlgorithm.getJWA(key.getAlgorithm()) + "\",\"typ\":\"JWT\"}");
    }

    if (signature == null) {
      // create signature
      sign();
    }

    return header + "." + payload + "." + signature;

  }

}
