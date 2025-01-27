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
import lombok.Getter;
import lombok.Setter;
import se.oidc.oidfed.md.lang.LanguageTaggedJson;
import se.oidc.oidfed.md.lang.OidcLangJsonSerializer;

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

  @Override public List<String> getLanguageTaggedParameters() {
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

    public CredentialIssuerMetadataBuilder authorizationServers (List<String> authorizationServers){
      this.metadata.authorizationServers = authorizationServers;
      return this;
    }

    public CredentialIssuerMetadataBuilder credentialEndpoint (String credentialEndpoint){
      this.metadata.credentialEndpoint = credentialEndpoint;
      return this;
    }

    public CredentialIssuerMetadataBuilder deferredCredentialEndpoint (String deferredCredentialEndpoint){
      this.metadata.deferredCredentialEndpoint = deferredCredentialEndpoint;
      return this;
    }

    public CredentialIssuerMetadataBuilder notificationEndpoint (String notificationEndpoint){
      this.metadata.notificationEndpoint = notificationEndpoint;
      return this;
    }

    public CredentialIssuerMetadataBuilder credentialResponseEncryption (CredentialResponseEncryption credentialResponseEncryption){
      this.metadata.credentialResponseEncryption = credentialResponseEncryption;
      return this;
    }

    public CredentialIssuerMetadataBuilder batchCredentialIssuance (BatchCredentialIssuance batchCredentialIssuance){
      this.metadata.batchCredentialIssuance = batchCredentialIssuance;
      return this;
    }

    public CredentialIssuerMetadataBuilder signedMetadata (String signedMetadata){
      this.metadata.signedMetadata = signedMetadata;
      return this;
    }

    public CredentialIssuerMetadataBuilder display (List<Display> display){
      this.metadata.display = display;
      return this;
    }

    public CredentialIssuerMetadataBuilder credentialConfiguration (String id, AbstractCredentialConfiguration credentialConfiguration){
      Map<String, AbstractCredentialConfiguration> credentialConfigurationMap = Optional.ofNullable(
        this.metadata.getCredentialConfigurationsSupported()).orElse(new HashMap<>());
      credentialConfigurationMap.put(id, credentialConfiguration);
      this.metadata.setCredentialConfigurationsSupported(credentialConfigurationMap);
      return this;
    }


    public CredentialIssuerMetadata build() {
      return this.metadata;
    }
  }

}
