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
package se.oidc.oidfed.md.wallet.credentialissuer;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.Getter;
import lombok.Setter;
import se.oidc.oidfed.md.lang.LanguageTaggedJson;
import se.oidc.oidfed.md.lang.OidcLangJsonSerializer;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Credential Issuer metadata
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CredentialIssuerMetadata implements LanguageTaggedJson {

  @JsonIgnore
  private List<String> languageTaggedParameters;

  @JsonIgnore
  @Getter
  private static final OidcLangJsonSerializer<CredentialIssuerMetadata> jsonSerializer =
      new OidcLangJsonSerializer<>(CredentialIssuerMetadata.class);

  /*
   * Metadata parameters defined in this extension to BasicASMetadata
   */
  @JsonProperty("credential_issuer")
  @Getter
  @Setter
  private String credentialIssuer;

  @JsonProperty("authorization_servers")
  @Getter
  @Setter
  protected List<String> authorizationServers;

  @JsonProperty("credential_endpoint")
  @Getter
  @Setter
  protected String credentialEndpoint;

  @JsonProperty("deferred_credential_endpoint")
  @Getter
  @Setter
  protected String deferredCredentialEndpoint;

  @JsonProperty("notification_endpoint")
  @Getter
  @Setter
  protected String notificationEndpoint;

  @JsonProperty("credential_response_encryption")
  @Getter
  @Setter
  protected CredentialResponseEncryption credentialResponseEncryption;

  @JsonProperty("batch_credential_issuance")
  @Getter
  @Setter
  protected BatchCredentialIssuance batchCredentialIssuance;

  @JsonProperty("signed_metadata")
  @Getter
  @Setter
  protected String signedMetadata;

  @JsonProperty("display")
  @Getter
  @Setter
  protected List<Display> display;

  @JsonProperty("credential_configurations_supported")
  @Getter
  @Setter
  protected Map<String, AbstractCredentialConfiguration> credentialConfigurationsSupported;

  /**
   * Constructor
   */
  public CredentialIssuerMetadata() {
    this.languageTaggedParameters = List.of();
  }

  /** {@inheritDoc} */
  public String toJson(final boolean prettyPrinting) throws JsonProcessingException {
    return jsonSerializer.setPrettyPrinting(prettyPrinting).toJson(this);
  }

  /** {@inheritDoc} */
  public Map<String, Object> toJsonObject() throws JsonProcessingException {
    return jsonSerializer.toJsonObject(this);
  }

  /**
   * Creates builder class
   *
   * @return builder
   */
  public static CredentialIssuerMetadataBuilder builder() {
    return new CredentialIssuerMetadataBuilder();
  }

  @Override
  public List<String> getLanguageTaggedParameters() {
    return this.languageTaggedParameters;
  }

  /**
   * Builder class
   */
  public static class CredentialIssuerMetadataBuilder {

    CredentialIssuerMetadata metadata;

    /**
     * Private constructor
     */
    private CredentialIssuerMetadataBuilder() {
      metadata = new CredentialIssuerMetadata();
    }

    public CredentialIssuerMetadataBuilder credentialIssuer(final String credentialIssuer) {
      this.metadata.credentialIssuer = credentialIssuer;
      return this;
    }

    public CredentialIssuerMetadataBuilder authorizationServers(List<String> authorizationServers) {
      this.metadata.authorizationServers = authorizationServers;
      return this;
    }

    public CredentialIssuerMetadataBuilder credentialEndpoint(String credentialEndpoint) {
      this.metadata.credentialEndpoint = credentialEndpoint;
      return this;
    }

    public CredentialIssuerMetadataBuilder deferredCredentialEndpoint(String deferredCredentialEndpoint) {
      this.metadata.deferredCredentialEndpoint = deferredCredentialEndpoint;
      return this;
    }

    public CredentialIssuerMetadataBuilder notificationEndpoint(String notificationEndpoint) {
      this.metadata.notificationEndpoint = notificationEndpoint;
      return this;
    }

    public CredentialIssuerMetadataBuilder credentialResponseEncryption(
        CredentialResponseEncryption credentialResponseEncryption) {
      this.metadata.credentialResponseEncryption = credentialResponseEncryption;
      return this;
    }

    public CredentialIssuerMetadataBuilder batchCredentialIssuance(BatchCredentialIssuance batchCredentialIssuance) {
      this.metadata.batchCredentialIssuance = batchCredentialIssuance;
      return this;
    }

    public CredentialIssuerMetadataBuilder display(List<Display> display) {
      this.metadata.display = display;
      return this;
    }

    public CredentialIssuerMetadataBuilder credentialConfiguration(String id,
        AbstractCredentialConfiguration credentialConfiguration) {
      Map<String, AbstractCredentialConfiguration> credentialConfigurationMap = Optional.ofNullable(
          this.metadata.getCredentialConfigurationsSupported()).orElse(new HashMap<>());
      credentialConfigurationMap.put(id, credentialConfiguration);
      this.metadata.setCredentialConfigurationsSupported(credentialConfigurationMap);
      return this;
    }

    /**
     * Builds and returns the {@link CredentialIssuerMetadata} object that has been configured using the builder methods
     * of this class.
     *
     * @return the constructed {@link CredentialIssuerMetadata} instance
     */
    public CredentialIssuerMetadata build() {
      return this.metadata;
    }

    /**
     * Constructs a {@link CredentialIssuerMetadata} object with signed metadata.
     * <p>
     * This method includes a signed JSON Web Token (JWT) that represents the metadata of the credential issuer, using
     * the provided signer, algorithm, and key identifier (kid).
     *
     * @param signer the {@link JWSSigner} to use for signing the metadata
     * @param algorithm the {@link JWSAlgorithm} to use for the digital signature
     * @param kid the key identifier (kid) to include in the JWT header
     * @return a {@link CredentialIssuerMetadata} object with signed metadata
     * @throws JOSEException if an error occurs while signing the metadata
     * @throws JsonProcessingException if an error occurs while processing metadata as JSON
     * @throws CertificateEncodingException if an error occurs while encoding the certificate chain
     */
    public CredentialIssuerMetadata buildWithSignedMetadata(@Nonnull final JWSSigner signer,
        @Nonnull final JWSAlgorithm algorithm, @Nullable final String kid)
        throws JOSEException, JsonProcessingException, CertificateEncodingException {
      return this.buildWithSignedMetadata(signer, algorithm, kid, null);
    }

    /**
     * Constructs a {@link CredentialIssuerMetadata} object with signed metadata. This method includes a signed JSON Web
     * Token (JWT) representing the metadata of the credential issuer, utilizing the provided signer, algorithm, and
     * certificate chain.
     *
     * @param signer the {@link JWSSigner} to use for signing the metadata
     * @param algorithm the {@link JWSAlgorithm} to use for creating the digital signature
     * @param chain the certificate chain to include in the JWT header
     * @return a {@link CredentialIssuerMetadata} object with signed metadata
     * @throws JOSEException if an error occurs during the signing process
     * @throws JsonProcessingException if an error occurs while converting metadata to JSON
     * @throws CertificateEncodingException if an error occurs while encoding the certificate chain
     */
    public CredentialIssuerMetadata buildWithSignedMetadata(@Nonnull final JWSSigner signer,
        @Nonnull final JWSAlgorithm algorithm, @Nullable final List<X509Certificate> chain)
        throws JOSEException, JsonProcessingException, CertificateEncodingException {
      return this.buildWithSignedMetadata(signer, algorithm, null, chain);
    }

    /**
     * Constructs a {@link CredentialIssuerMetadata} object with signed metadata. This method includes a signed JSON Web
     * Token (JWT) representing the metadata of the credential issuer, utilizing the provided signer, algorithm, key
     * identifier (kid), and certificate chain.
     *
     * @param signer the {@link JWSSigner} used to sign the metadata
     * @param algorithm the {@link JWSAlgorithm} used to create the digital signature
     * @param kid the key identifier (kid) to be included in the JWT header
     * @param chain the certificate chain to include in the JWT header. If null or empty, no certificate chain is
     *     added
     * @return a {@link CredentialIssuerMetadata} object containing the signed metadata
     * @throws JOSEException if an error occurs during the signing process
     * @throws JsonProcessingException if an error occurs while converting metadata to JSON
     * @throws CertificateEncodingException if an error occurs while encoding the certificate chain
     */
    public CredentialIssuerMetadata buildWithSignedMetadata(@Nonnull final JWSSigner signer,
        @Nonnull final JWSAlgorithm algorithm, @Nullable final String kid,
        @Nullable final List<X509Certificate> chain)
        throws JOSEException, JsonProcessingException, CertificateEncodingException {

      final JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
          .issuer(this.metadata.getCredentialIssuer())
          .subject(this.metadata.getCredentialIssuer())
          .issueTime(new Date());

      // Ensure signed metadata is not set, and include other claims in JWT
      this.metadata.setSignedMetadata(null);
      this.metadata.toJsonObject().forEach(claimsSetBuilder::claim);

      final JWSHeader.Builder headerBuilder = new JWSHeader.Builder(algorithm);
      if (kid != null && !kid.isEmpty()) {
        headerBuilder.keyID(kid);
      }
      if (chain != null && !chain.isEmpty()) {
        List<Base64> encodedChain = new ArrayList<>();
        for (X509Certificate cert : chain) {
          encodedChain.add(Base64.encode(cert.getEncoded()));
        }
        headerBuilder.x509CertChain(encodedChain);
      }

      final SignedJWT jwt = new SignedJWT(
          headerBuilder.build(),
          claimsSetBuilder.build());
      jwt.sign(signer);

      this.metadata.setSignedMetadata(jwt.serialize());
      return this.metadata;
    }
  }

}
