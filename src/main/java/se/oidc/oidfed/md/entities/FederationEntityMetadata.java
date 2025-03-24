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
package se.oidc.oidfed.md.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.Getter;
import lombok.Setter;
import se.oidc.oidfed.md.lang.OidcLangJsonSerializer;

import java.util.List;
import java.util.Map;

/**
 * Federation endpoint metadata
 */
public class FederationEntityMetadata extends AbstractOidcFedMetadata {

  @JsonIgnore
  @Getter
  public static final OidcLangJsonSerializer<FederationEntityMetadata> jsonSerializer =
      new OidcLangJsonSerializer<>(FederationEntityMetadata.class);

  public FederationEntityMetadata() {
    this.addLanguageParametersTags(List.of());
  }

  /**
   * OPTIONAL. The fetch endpoint described in Section 8.1. This URL MUST use the https scheme and MAY contain port,
   * path, and query parameter components; it MUST NOT contain a fragment component. Intermediate Entities and Trust
   * Anchors MUST publish a federation_fetch_endpoint. Leaf Entities MUST NOT.
   */
  @JsonProperty("federation_fetch_endpoint")
  @Getter
  @Setter
  private String federationFetchEndpoint;

  /**
   * OPTIONAL. The list endpoint described in Section 8.2. This URL MUST use the https scheme and MAY contain port,
   * path, and query parameter components; it MUST NOT contain a fragment component. Intermediate Entities and Trust
   * Anchors MUST publish a federation_list_endpoint. Leaf Entities MUST NOT.
   */
  @JsonProperty("federation_list_endpoint")
  @Getter
  @Setter
  private String federationListEndpoint;

  /**
   * OPTIONAL. The resolve endpoint described in Section 8.3. This URL MUST use the https scheme and MAY contain port,
   * path, and query parameter components; it MUST NOT contain a fragment component. Any federation Entity MAY publish a
   * federation_resolve_endpoint.
   */
  @JsonProperty("federation_resolve_endpoint")
  @Getter
  @Setter
  private String federationResolveEndpoint;

  /**
   * OPTIONAL. The Trust Mark status endpoint described in Section 8.4. Trust Mark Issuers SHOULD publish a
   * federation_trust_mark_status_endpoint. This URL MUST use the https scheme and MAY contain port, path, and query
   * parameter components; it MUST NOT contain a fragment component.
   */
  @JsonProperty("federation_trust_mark_status_endpoint")
  @Getter
  @Setter
  private String federationTrustMarkStatusEndpoint;

  /**
   * OPTIONAL. The endpoint described in Section 8.5. This URL MUST use the https scheme and MAY contain port, path, and
   * query parameter components; it MUST NOT contain a fragment component. Trust Mark Issuers MAY publish a
   * federation_trust_mark_list_endpoint.
   */
  @JsonProperty("federation_trust_mark_list_endpoint")
  @Getter
  @Setter
  private String federationTrustMarkListEndpoint;

  /**
   * OPTIONAL. The endpoint described in Section 8.6. This URL MUST use the https scheme and MAY contain port, path, and
   * query parameter components; it MUST NOT contain a fragment component. Trust Mark Issuers MAY publish a
   * federation_trust_mark_endpoint.
   */
  @JsonProperty("federation_trust_mark_endpoint")
  @Getter
  @Setter
  private String federationTrustMarkEndpoint;

  /**
   * OPTIONAL. The endpoint described in Section 8.7. This URL MUST use the https scheme and MAY contain port, path, and
   * query parameter components; it MUST NOT contain a fragment component. All Federation Entities MAY publish a
   * federation_historical_keys_endpoint.
   */
  @JsonProperty("federation_historical_keys_endpoint")
  @Getter
  @Setter
  private String federationHistoricalKeysEndpoint;

  /**
   * The `federationDiscoveryEndpoint` field represents the URL endpoint for the discovery of federation metadata. It is
   * used in the context of OIDC federation to locate and retrieve metadata associated with a federation entity.
   */
  @JsonProperty("federation_discovery_endpoint")
  @Getter
  @Setter
  private String federationDiscoveryEndpoint;

  /**
   * OPTIONAL. JSON array containing a list of the supported JWS [RFC7515] algorithms (alg values) for signing the JWT
   * [RFC7519] used for private_key_jwt when authenticating to federation endpoints, as described in Section 8.8. No
   * default algorithms are implied if this entry is omitted. Servers SHOULD support RS256. The value none MUST NOT be
   * used.
   */
  @JsonProperty("endpoint_auth_signing_alg_values_supported")
  private List<String> endpointAuthSigningAlgValuesSupported;

  /** {@inheritDoc} */
  @Override
  public String toJson(final boolean prettyPrinting) throws JsonProcessingException {
    return jsonSerializer.setPrettyPrinting(prettyPrinting).toJson(this);
  }

  /** {@inheritDoc} */
  @Override
  public Map<String, Object> toJsonObject() throws JsonProcessingException {
    return jsonSerializer.toJsonObject(this);
  }

  /**
   * Creates builder class for Federation endpoint metadata
   *
   * @return builder
   */
  public static FederationEntityMetadataBuilder builder() {
    return new FederationEntityMetadataBuilder();
  }

  /**
   * Builder class for federation endpoint metadata
   */
  public static class FederationEntityMetadataBuilder
      extends AbstractOidcFedMetadataBuilder<FederationEntityMetadata, FederationEntityMetadataBuilder> {

    /**
     * Private constructor
     */
    private FederationEntityMetadataBuilder() {
      super(new FederationEntityMetadata());
    }

    public FederationEntityMetadataBuilder federationFetchEndpoint(final String federationFetchEndpoint) {
      this.metadata.federationFetchEndpoint = federationFetchEndpoint;
      return this;
    }

    public FederationEntityMetadataBuilder federationListEndpoint(final String federationListEndpoint) {
      this.metadata.federationListEndpoint = federationListEndpoint;
      return this;
    }

    public FederationEntityMetadataBuilder federationResolveEndpoint(final String federationResolveEndpoint) {
      this.metadata.federationResolveEndpoint = federationResolveEndpoint;
      return this;
    }

    public FederationEntityMetadataBuilder federationTrustMarkStatusEndpoint(
        final String federationTrustMarkStatusEndpoint) {
      this.metadata.federationTrustMarkStatusEndpoint = federationTrustMarkStatusEndpoint;
      return this;
    }

    public FederationEntityMetadataBuilder federationTrustMarkListEndpoint(
        final String federationTrustMarkListEndpoint) {
      this.metadata.federationTrustMarkListEndpoint = federationTrustMarkListEndpoint;
      return this;
    }

    public FederationEntityMetadataBuilder federationTrustMarkEndpoint(final String federationTrustMarkEndpoint) {
      this.metadata.federationTrustMarkEndpoint = federationTrustMarkEndpoint;
      return this;
    }

    public FederationEntityMetadataBuilder federationHistoricalKeysEndpoint(
        final String federationHistoricalKeysEndpoint) {
      this.metadata.federationHistoricalKeysEndpoint = federationHistoricalKeysEndpoint;
      return this;
    }

    public FederationEntityMetadataBuilder federationDiscoveryEndpoint(final String federationDiscoveryEndpoint) {
      this.metadata.federationDiscoveryEndpoint = federationDiscoveryEndpoint;
      return this;
    }

    public FederationEntityMetadataBuilder endpointAuthSigningAlgValuesSupported(
        final List<String> endpointAuthSigningAlgValuesSupported) {
      this.metadata.endpointAuthSigningAlgValuesSupported = endpointAuthSigningAlgValuesSupported;
      return this;
    }

    /** {@inheritDoc} */
    @Override
    protected FederationEntityMetadataBuilder getReturnedBuilderInstance() {
      return this;
    }

    /** {@inheritDoc} */
    @Override
    public FederationEntityMetadata build() {
      return this.metadata;
    }
  }

}
