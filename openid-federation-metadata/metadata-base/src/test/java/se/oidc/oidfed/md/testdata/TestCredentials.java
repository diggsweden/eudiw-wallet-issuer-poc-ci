/*
 * Copyright 2024 OIDC Sweden
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.oidc.oidfed.md.testdata;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import lombok.Getter;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * Credentials for unit tests
 */
public class TestCredentials {

  @Getter
  public static PkiCredential p256Credential;
  @Getter
  public static PkiCredential p521Credential;
  @Getter
  public static PkiCredential rsa3072Credential;


  public static final char[] pwd = "Test1234".toCharArray();

  static {
    try {
      final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(TestCredentials.class.getResourceAsStream("/test-keys.jks"), pwd);

      p256Credential = new KeyStoreCredential(keyStore, "p256", pwd);
      p521Credential = new KeyStoreCredential(keyStore, "p521", pwd);
      rsa3072Credential = new KeyStoreCredential(keyStore, "rsa3072", pwd);

    }
    catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static JWKSet getJwkSet(final X509Certificate... certificate) {

    return new JWKSet(
        Arrays.stream(certificate)
            .map(cert -> {
              try {
                return JWK.parse(cert);
              }
              catch (final JOSEException e) {
                throw new RuntimeException(e);
              }
            })
            .collect(Collectors.toList())
    );

  }

}
