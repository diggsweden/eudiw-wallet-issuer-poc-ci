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
 * Description
 */

@Data
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public abstract class AbstractCredentialConfiguration {

  @JsonProperty("format")
  protected String format;

  @JsonProperty("scope")
  protected String scope;

  @JsonProperty("cryptographic_binding_methods_supported")
  protected List<String> cryptographicBindingMethodsSupported;

  @JsonProperty("credential_signing_alg_values_supported")
  protected List<String> credentialSigningAlgValuesSupported;

  @JsonProperty("proof_types_supported")
  protected Map<String, ProofType> proofTypesSupported;

  @JsonProperty("display")
  protected List<Display> display;

  @Data
  @JsonInclude(JsonInclude.Include.NON_NULL)
  protected static class ProofType {

    public ProofType(List<String> proofSigningAlgValuesSupported) {
      this.proofSigningAlgValuesSupported = proofSigningAlgValuesSupported;
    }

    @JsonProperty("proof_signing_alg_values_supported")
    private List<String> proofSigningAlgValuesSupported;

  }

  protected static abstract class AbstractCredentialConfigurationBuilder<T extends AbstractCredentialConfiguration, B extends AbstractCredentialConfigurationBuilder<?,?>> {

    protected final T credentialConfiguration;

    public AbstractCredentialConfigurationBuilder(final T credentialConfiguration) {
      this.credentialConfiguration = credentialConfiguration;
    }

    protected abstract B getBuilder();

    public B format (String format){
      this.credentialConfiguration.setFormat(format);
      return getBuilder();
    }


    public B scope (String scope){
      this.credentialConfiguration.setScope(scope);
      return getBuilder();
    }

    public B cryptographicBindingMethodsSupported (List<String> cryptographicBindingMethodsSupported){
      this.credentialConfiguration.setCryptographicBindingMethodsSupported(cryptographicBindingMethodsSupported);
      return getBuilder();
    }

    public B credentialSigningAlgValuesSupported (List<String> credentialSigningAlgValuesSupported){
      this.credentialConfiguration.setCredentialSigningAlgValuesSupported(credentialSigningAlgValuesSupported);
      return getBuilder();
    }

    public B proofType (String id, ProofType proofType){
      Map<String, ProofType> proofTypeMap = Optional.ofNullable(this.credentialConfiguration.getProofTypesSupported())
        .orElse(new HashMap<>());
      proofTypeMap.put(id, proofType);
      this.credentialConfiguration.setProofTypesSupported(proofTypeMap);
      return getBuilder();
    }

    public B display (List<Display> display){
      this.credentialConfiguration.setDisplay(display);
      return getBuilder();
    }

    public AbstractCredentialConfiguration build() {
      return this.credentialConfiguration;
    }
  }
}
