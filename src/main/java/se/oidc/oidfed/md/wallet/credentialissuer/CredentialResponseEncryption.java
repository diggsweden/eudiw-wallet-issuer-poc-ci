package se.oidc.oidfed.md.wallet.credentialissuer;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CredentialResponseEncryption {

  @JsonProperty("alg_values_supported")
  private List<String> algValuesSupported;

  @JsonProperty("enc_values_supported")
  private List<String> encValuesSupported;

  @JsonProperty("encryption_required")
  private boolean encryptionRequired;

}
