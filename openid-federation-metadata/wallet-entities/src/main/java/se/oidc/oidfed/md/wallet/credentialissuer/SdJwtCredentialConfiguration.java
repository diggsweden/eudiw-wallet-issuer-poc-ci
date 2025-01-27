package se.oidc.oidfed.md.wallet.credentialissuer;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Credential Configuration for IETF SD-JWT verifiable credentials
 */
@Data
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SdJwtCredentialConfiguration extends AbstractCredentialConfiguration {

  /**
   * REQUIRED. String designating the type of a Credential, as defined in [I-D.ietf-oauth-sd-jwt-vc].
   */
  @JsonProperty("vct")
  private String vct;

  /**
   * OPTIONAL. Object containing a list of name/value pairs, where each name identifies a claim about the subject offered in the Credential.
   */
  @JsonProperty("claims")
  private Map<String, Object> claims;

  /**
   * OPTIONAL. An array of the claim name values that lists them in the order they should be displayed by the Wallet.
   */
  @JsonProperty("order")
  private List<String> order;

  public static SdJwtCredentialConfigurationBuilder builder() {
    return new SdJwtCredentialConfigurationBuilder();
  }

  public static class SdJwtCredentialConfigurationBuilder
    extends AbstractCredentialConfigurationBuilder<SdJwtCredentialConfiguration, SdJwtCredentialConfigurationBuilder>{

    public SdJwtCredentialConfigurationBuilder() {
      super(new SdJwtCredentialConfiguration());
    }

    @Override protected SdJwtCredentialConfigurationBuilder getBuilder() {
      return this;
    }

    /**
     * Sets the vct value in the SdJwtCredentialConfiguration and returns the builder instance.
     *
     * @param vct the verifiable credential type value to set
     * @return the IsoMdlCredentialConfigurationBuilder instance
     */
    public SdJwtCredentialConfigurationBuilder vct (String vct) {
      this.credentialConfiguration.setVct(vct);
      return this;
    }

    /**
     * Sets the claims for the SdJwtCredentialConfiguration and returns the IsoMdlCredentialConfigurationBuilder instance.
     *
     * @param claims a map containing the list of name/value pairs for the claims
     * @return the IsoMdlCredentialConfigurationBuilder instance
     */
    public SdJwtCredentialConfigurationBuilder claims(Map<String, Object> claims) {
      this.credentialConfiguration.setClaims(claims);
      return this;
    }

    /**
     * Adds a claim to the credential configuration.
     *
     * @param id the ID of the claim
     * @param claim the Claim object to be added
     * @return the IsoMdlCredentialConfigurationBuilder instance
     */
    public SdJwtCredentialConfigurationBuilder claim(String id, Claim claim) {
      Map<String, Object> claimMap = Optional.ofNullable(this.credentialConfiguration.getClaims()).orElse(new HashMap<>());
      claimMap.put(id, claim);
      this.credentialConfiguration.setClaims(claimMap);
      return this;
    }

    /**
     * Sets the order of claims in display.
     *
     * @param order the list of claim names in the order they should be displayed
     * @return the IsoMdlCredentialConfigurationBuilder instance
     */
    public SdJwtCredentialConfigurationBuilder order(List<String> order) {
      this.credentialConfiguration.setOrder(order);
      return this;
    }

  }
}
