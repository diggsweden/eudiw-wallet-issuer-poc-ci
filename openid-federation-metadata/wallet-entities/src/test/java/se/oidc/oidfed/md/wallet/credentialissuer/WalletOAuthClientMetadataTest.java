package se.oidc.oidfed.md.wallet.credentialissuer;

import com.nimbusds.jose.jwk.JWKSet;
import se.oidc.oidfed.md.wallet.data.TestData;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;
import se.oidc.oidfed.md.lang.LanguageObject;
import se.oidc.oidfed.md.entities.ClientMetadata;
import se.oidc.oidfed.md.JWKUtils;

import java.util.List;

/**
 * Description
 */
@Slf4j
class WalletOAuthClientMetadataTest {
  
  
  @Test
  public void testClientOAuthMetadata() throws Exception{

    ClientMetadata clientMetadata = ClientMetadata.oauthClientMetadataBuilder()
      .organizationName(LanguageObject.builder(String.class)
        .defaultValue("Organization inc")
        .langValue("sv", "Organisation AB")
        .langValue("en", "Organization inc")
        .build())
      .grantTypes(List.of("grant1", "grant2"))
      .scope("scope")
      .build();

    log.info("Client metadata: \n{}", clientMetadata.toJson(true));

    JSONAssert.assertEquals("{\n"
      + "  \"organization_name\" : \"Organization inc\",\n"
      + "  \"grant_types\" : [ \"grant1\", \"grant2\" ],\n"
      + "  \"organization_name#sv\" : \"Organisation AB\",\n"
      + "  \"organization_name#en\" : \"Organization inc\",\n"
      + "  \"scope\" : \"scope\"\n"
      + "}",
      clientMetadata.toJson(false), JSONCompareMode.LENIENT);

  }

  @Test
  public void testWalletMetadata() throws Exception {

    WalletOAuthClientMetadata walletOAuthClientMetadata = WalletOAuthClientMetadata.walletOauthClientMetadataBuilder()
      .credentialOfferEndpoint("https://example.com/credential-offer-endpoint")
      .clientName(LanguageObject.builder(String.class)
        .build())
      .organizationName(LanguageObject.builder(String.class)
        .defaultValue("Organization inc")
        .langValue("sv", "Organisation AB")
        .langValue("en", "Organization inc")
        .build())
      .grantTypes(List.of("grant1", "grant2"))
      .scope("scope")
      .build();

    log.info("Client metadata: \n{}", walletOAuthClientMetadata.toJson(true));

    JSONAssert.assertEquals("{\n"
      + "  \"credential_offer_endpoint\" : \"https://example.com/credential-offer-endpoint\",\n"
      + "  \"organization_name\" : \"Organization inc\",\n"
      + "  \"grant_types\" : [ \"grant1\", \"grant2\" ],\n"
      + "  \"organization_name#sv\" : \"Organisation AB\",\n"
      + "  \"organization_name#en\" : \"Organization inc\",\n"
      + "  \"scope\" : \"scope\"\n"
      + "}",
      walletOAuthClientMetadata.toJson(false), JSONCompareMode.LENIENT);
  }

  @Test
  public void testReaslisticWalletMetadata() throws Exception {

    WalletOAuthClientMetadata walletOAuthClientMetadata = WalletOAuthClientMetadata.walletOauthClientMetadataBuilder()
      .jwkSet(new JWKSet(List.of(JWKUtils.getJwkWithKid(TestData.testEntityCert, "wallet-1", false))))
      .redirectUris(List.of("https://example.com/redirectUri"))
      .grantTypes(List.of("authorization_code"))
      .tokenEndpointAuthMethod("private_key_jwt")
      .softwareId("se-eudiwallet")
      .softwareVersion("0.0.1")
      .build();

    log.info("Client metadata: \n{}", walletOAuthClientMetadata.toJson(true));

    JSONAssert.assertEquals("{\n"
        + "  \"software_id\" : \"se-eudiwallet\",\n"
        + "  \"redirect_uris\" : [ \"https://example.com/redirectUri\" ],\n"
        + "  \"software_version\" : \"0.0.1\",\n"
        + "  \"jwks\" : {\n"
        + "    \"keys\" : [ {\n"
        + "      \"kty\" : \"EC\",\n"
        + "      \"crv\" : \"P-256\",\n"
        + "      \"kid\" : \"wallet-1\",\n"
        + "      \"x\" : \"VAIwQDxtPfh_057RJTW2WLafL9q9zQOr7krIt50c-hQ\",\n"
        + "      \"y\" : \"SawPLbJ_tb_iTS9tGXuR6iteg1uhYo1Brra4nlUYqJw\"\n"
        + "    } ]\n"
        + "  },\n"
        + "  \"grant_types\" : [ \"authorization_code\" ],\n"
        + "  \"token_endpoint_auth_method\" : \"private_key_jwt\"\n"
        + "}",
      walletOAuthClientMetadata.toJson(false), JSONCompareMode.LENIENT);
  }



}