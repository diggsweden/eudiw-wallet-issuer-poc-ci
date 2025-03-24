package se.oidc.oidfed.md.wallet.credentialissuer;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
import se.oidc.oidfed.md.entities.ClientMetadata;

/**
 * Wallet OAuth client metadata
 */
public class WalletOAuthClientMetadata extends ClientMetadata {

  /**
   * The optional credential offer endpoint of the wallet instance
   */
  @JsonProperty("credential_offer_endpoint")
  @Getter
  @Setter
  protected String credentialOfferEndpoint;

  /**
   * Creates a new instance of WalletOAuthClientMetadataBuilder.
   *
   * @return A new instance of WalletOAuthClientMetadataBuilder
   */
  public static WalletOAuthClientMetadataBuilder walletOauthClientMetadataBuilder() {
    return new WalletOAuthClientMetadataBuilder();
  }

  /**
   * A builder class for constructing Wallet OAuth client metadata.
   */
  public static class WalletOAuthClientMetadataBuilder extends ClientMetadata.ClientMetadataBuilder<WalletOAuthClientMetadata, WalletOAuthClientMetadataBuilder> {

    /**
     * Constructs a new WalletOAuthClientMetadataBuilder.
     */
    public WalletOAuthClientMetadataBuilder() {
      super(new WalletOAuthClientMetadata());
    }

    /**
     * Retrieves an instance of this builder. This Override is necessary to meet the requirements of the superclass
     *
     * @return An instance of WalletOAuthClientMetadataBuilder
     */
    @Override public WalletOAuthClientMetadataBuilder getSubClassBuilderInstance() {
      return this;
    }

    /**
     * Sets the credential offer endpoint for the Wallet OAuth client metadata.
     *
     * @param credentialOfferEndpoint the credential offer endpoint to be set
     * @return this WalletOAuthClientMetadataBuilder instance
     */
    public WalletOAuthClientMetadataBuilder credentialOfferEndpoint(String credentialOfferEndpoint) {
      this.metadata.credentialOfferEndpoint = credentialOfferEndpoint;
      return this;
    }

  }

}
