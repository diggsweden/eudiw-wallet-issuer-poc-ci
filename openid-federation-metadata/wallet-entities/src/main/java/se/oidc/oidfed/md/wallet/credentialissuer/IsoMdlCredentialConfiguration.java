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
 * Credential Configuration for ISO Mdl verifiable credentials
 */
@Data
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IsoMdlCredentialConfiguration extends AbstractCredentialConfiguration {

  /**
   *  REQUIRED. String identifying the Credential type, as defined in [ISO.18013-5].
   */
  @JsonProperty("doctype")
  private String doctype;

  /**
   * OPTIONAL. Object containing a list of name/value pairs, where the name is a certain namespace as defined in [ISO.18013-5] (or any
   * profile of it), and the value is an object. This object also contains a list of name/value pairs, where the name is a claim name
   * value that is defined in the respective namespace and is offered in the Credential..
   */
  @JsonProperty("claims")
  private Map<String, Map<String, Claim>> claims;

  /**
   * OPTIONAL. Array of namespaced claim name values that lists them in the order they should be displayed by the Wallet. The values MUST be
   * two strings separated by a tilde ('~') character, where the first string is a namespace value and a second is a claim name value.
   * For example, "org.iso.18013.5.1~given_name"
   */
  @JsonProperty("order")
  private List<String> order;

  public static IsoMdlCredentialConfigurationBuilder builder() {
    return new IsoMdlCredentialConfigurationBuilder();
  }

  public static class IsoMdlCredentialConfigurationBuilder
    extends AbstractCredentialConfigurationBuilder<IsoMdlCredentialConfiguration, IsoMdlCredentialConfigurationBuilder>{

    public IsoMdlCredentialConfigurationBuilder() {
      super(new IsoMdlCredentialConfiguration());
    }

    @Override protected IsoMdlCredentialConfigurationBuilder getBuilder() {
      return this;
    }

    /**
     * Sets the docType value in the IsoMdlCredentialConfiguration and returns the builder instance.
     *
     * @param docType the verifiable credential type value to set
     * @return the IsoMdlCredentialConfigurationBuilder instance
     */
    public IsoMdlCredentialConfigurationBuilder doctype (String docType) {
      this.credentialConfiguration.setDoctype(docType);
      return this;
    }

    /**
     * Adds a claim under a certain name space to the credential configuration.
     *
     * @param nameSpace the name space of the claim
     * @param claimName the ID of the claim
     * @param claim the Claim object to be added
     * @return the IsoMdlCredentialConfigurationBuilder instance
     */
    public IsoMdlCredentialConfigurationBuilder claim(String nameSpace, String claimName, Claim claim) {
      Map<String, Map<String, Claim>> nameSpaceMap = Optional.ofNullable(this.credentialConfiguration.getClaims()).orElse(new HashMap<>());
      Map<String, Claim> claimMap = Optional.ofNullable(nameSpaceMap.get(nameSpace)).orElse(new HashMap<>());
      claimMap.put(claimName, claim);
      nameSpaceMap.put(nameSpace, claimMap);
      this.credentialConfiguration.setClaims(nameSpaceMap);
      return this;
    }

    /**
     * Sets the order of claims in display.
     *
     * @param order the list of claim names in the order they should be displayed
     * @return the IsoMdlCredentialConfigurationBuilder instance
     */
    public IsoMdlCredentialConfigurationBuilder order(List<String> order) {
      this.credentialConfiguration.setOrder(order);
      return this;
    }

  }
}
