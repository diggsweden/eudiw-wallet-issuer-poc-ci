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
 * Credential Configuration for JSON LD verifiable credentials
 */
@Data
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class JsonLdCredentialConfiguration extends AbstractCredentialConfiguration {

  @JsonProperty("credential_definition")
  private JsonLdCredentialDefinition credentialDefinition;

  /**
   * OPTIONAL. Array of the claim name values that lists them in the order they should be displayed by the Wallet.
   */
  @JsonProperty("order")
  private List<String> order;

  public static JsonLdCredentialConfigurationBuilder builder() {
    return new JsonLdCredentialConfigurationBuilder();
  }

  public static class JsonLdCredentialConfigurationBuilder extends AbstractCredentialConfigurationBuilder<JsonLdCredentialConfiguration, JsonLdCredentialConfigurationBuilder>{

    public JsonLdCredentialConfigurationBuilder() {
      super(new JsonLdCredentialConfiguration());
    }

    /**
     * Sets the credential definition for the JsonLdCredentialConfigurationBuilder.
     *
     * @param credentialDefinition the JsonLdCredentialDefinition to be set
     * @return the JsonLdCredentialConfigurationBuilder instance with the updated credential definition
     */
    public JsonLdCredentialConfigurationBuilder credentialDefinition(JsonLdCredentialDefinition credentialDefinition) {
      this.credentialConfiguration.credentialDefinition = credentialDefinition;
      return this;
    }

    /**
     * Sets the order of claim name values that lists them in the order they should be displayed by the Wallet.
     *
     * @param order the list of claim name values to set the order
     * @return the JsonLdCredentialConfigurationBuilder instance
     */
    public JsonLdCredentialConfigurationBuilder order(List<String> order) {
      this.credentialConfiguration.order = order;
      return this;
    }

    @Override protected JsonLdCredentialConfigurationBuilder getBuilder() {
      return this;
    }
  }

  @Data
  @NoArgsConstructor
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class JsonLdCredentialDefinition {

    /**
     * REQUIRED. Array as defined in [VC_DATA], Section 4.1.
     */
    @JsonProperty("@context")
    public List<String> context;

    /**
     * REQUIRED. Array designating the types a certain credential type supports, according to [VC_DATA], Section 4.3.
     */
    @JsonProperty("type")
    public List<String> type;

    /**
     * Object containing a list of name/value pairs, where each name identifies a claim offered in the Credential. The value can be another
     * such claim object (nested data structures), or an array of such claim objects.
     */
    @JsonProperty("credentialSubject")
    public Map<String, Object> credentialSubject;

    /**
     * Creates a new instance of JsonLdCredentialDefinitionBuilder.
     *
     * @return a new JsonLdCredentialDefinitionBuilder instance
     */
    public static JsonLdCredentialDefinitionBuilder builder() {
      return new JsonLdCredentialDefinitionBuilder();
    }

    /**
     * A builder class for creating JsonLdCredentialDefinition instances.
     */
    public static class JsonLdCredentialDefinitionBuilder {

      private final JsonLdCredentialDefinition credentialDefinition;
      private JsonLdCredentialDefinitionBuilder() {
        this.credentialDefinition = new JsonLdCredentialDefinition();
      }

      /**
       * Sets the context for the JsonLdCredentialDefinition.
       *
       * @param context a list of context strings to set
       * @return the JsonLdCredentialDefinitionBuilder instance with the updated context
       */
      public JsonLdCredentialDefinitionBuilder context(List<String> context) {
        this.credentialDefinition.context = context;
        return this;
      }

      /**
       * Sets the types of the JsonLdCredentialDefinition.
       *
       * @param type a list of strings representing the types to set
       * @return the JsonLdCredentialDefinitionBuilder instance with the updated types
       */
      public JsonLdCredentialDefinitionBuilder type(List<String> type) {
        this.credentialDefinition.type = type;
        return this;
      }

      /**
       * Sets the credentialSubject field of the JsonLdCredentialDefinitionBuilder instance.
       * If this function is used after setting values with "credentialSubjectClaim()", then these values will be lost.
       *
       * @param credentialSubject a Map representing the credential subject information
       * @return the JsonLdCredentialDefinitionBuilder instance with the updated credentialSubject field
       */
      public JsonLdCredentialDefinitionBuilder credentialSubject(Map<String, Object> credentialSubject) {
        this.credentialDefinition.credentialSubject = credentialSubject;
        return this;
      }

      /**
       * Sets a claim for the credential subject using the provided ID and claim object.
       * If nested objects are required, then use "credentialSubject()" to set a complete Map structure with nested objects.
       *
       * @param claimName the name of the claim
       * @param claim the claim object containing information about the claim
       * @return the JsonLdCredentialDefinitionBuilder instance with the updated credentialSubject field
       */
      public JsonLdCredentialDefinitionBuilder credentialSubjectClaim(String claimName, Claim claim) {
        Map<String, Object> objectMap = Optional.ofNullable(this.credentialDefinition.credentialSubject).orElse(new HashMap<>());
        objectMap.put(claimName, claim);
        this.credentialDefinition.credentialSubject = objectMap;
        return this;
      }

      /**
       * Retrieves the built JsonLdCredentialDefinition instance.
       *
       * @return the built JsonLdCredentialDefinition instance
       */
      public JsonLdCredentialDefinition build() {
        return this.credentialDefinition;
      }

    }


  }

}
