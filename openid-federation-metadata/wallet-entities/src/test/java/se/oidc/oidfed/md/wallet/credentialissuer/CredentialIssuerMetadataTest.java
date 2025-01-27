package se.oidc.oidfed.md.wallet.credentialissuer;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.util.List;

/**
 * Description
 */
@Slf4j
class CredentialIssuerMetadataTest {

  @Test
  void testSdJwtCredentialIssuerMetadata() throws Exception {

    CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
      .credentialIssuer("https://example.com/credential-issuer")
      .authorizationServers(List.of("https://example.com/as-server"))
      .credentialEndpoint("https://example.com/credential-endpoint")
      .deferredCredentialEndpoint("https://example.com/deferred-credential-endpoint")
      .notificationEndpoint("https://example.com/notification-endpoint")
      .credentialResponseEncryption(CredentialResponseEncryption.builder()
        .algValuesSupported(List.of("RS256", "ES256"))
        .encValuesSupported(List.of("algo1", "algo2"))
        .encryptionRequired(false)
        .build())
      .batchCredentialIssuance(new BatchCredentialIssuance(100))
      .signedMetadata("signed_metadata_jwt")
      .display(List.of(Display.builder()
        .name("Credential Issuer Name")
        .locale("en")
        .logo(new Display.Image("https://example.com/logo", "Logo"))
        .build()))
      .credentialConfiguration("SD_JWT_VC_example_in_OpenID4VCI", SdJwtCredentialConfiguration.builder()
        .format("vc+sd-jwt")
        .scope("SD_JWT_VC_example_in_OpenID4VCI")
        .cryptographicBindingMethodsSupported(List.of("binding1", "binding2"))
        .credentialSigningAlgValuesSupported(List.of("RS256", "ES256"))
        .proofType("jwt", new SdJwtCredentialConfiguration.ProofType(List.of("ES256")))
        .display(List.of(
          Display.builder()
            .name("Credential name")
            .locale("sv")
            .logo(new Display.Image("https://example.com/logo", "Logo"))
            .description("Description")
            .backgroundColor("#000000")
            .backgroundImage(new Display.Image("https://example.com/background-image"))
            .textColor("#FFFFFF")
            .build()))
        .vct("SD_JWT_VC_example_in_OpenID4VCI")
        .claim("given_name", Claim.builder()
          .mandatory(true)
          .valueType("text")
          .display(List.of(
            Display.builder()
            .name("Given Name")
            .locale("en")
            .build(),
            Display.builder()
            .name("Förnamn")
            .locale("sv")
            .build()
            ))
          .build())
        .claim("family_name", Claim.builder()
          .mandatory(true)
          .valueType("text")
          .display(List.of(
            Display.builder()
            .name("Surname")
            .locale("en")
            .build(),
            Display.builder()
            .name("Efternamn")
            .locale("sv")
            .build()
            ))
          .build())
        .order(List.of("given_name","family_name"))
        .build())
      .build();

    log.info("JD JWT Credential Issuer Metadata: \n{}", credentialIssuerMetadata.toJson(true));
  }

  @Test
  void testIsoMdlCredentialIssuerMetadata() throws Exception {

    CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
      .credentialIssuer("https://example.com/credential-issuer")
      .authorizationServers(List.of("https://example.com/as-server"))
      .credentialEndpoint("https://example.com/credential-endpoint")
      .deferredCredentialEndpoint("https://example.com/deferred-credential-endpoint")
      .notificationEndpoint("https://example.com/notification-endpoint")
      .credentialResponseEncryption(CredentialResponseEncryption.builder()
        .algValuesSupported(List.of("RS256", "ES256"))
        .encValuesSupported(List.of("algo1", "algo2"))
        .encryptionRequired(false)
        .build())
      .batchCredentialIssuance(new BatchCredentialIssuance(100))
      .signedMetadata("signed_metadata_jwt")
      .display(List.of(Display.builder()
        .name("Credential Issuer Name")
        .locale("en")
        .logo(new Display.Image("https://example.com/logo", "Logo"))
        .build()))
      .credentialConfiguration("org.iso.18013.5.1.mDL", IsoMdlCredentialConfiguration.builder()
        .format("vc+sd-jwt")
        .scope("org.iso.18013.5.1.mDL")
        .cryptographicBindingMethodsSupported(List.of("binding1", "binding2"))
        .credentialSigningAlgValuesSupported(List.of("RS256", "ES256"))
        .proofType("jwt", new AbstractCredentialConfiguration.ProofType(List.of("ES256")))
        .display(List.of(
          Display.builder()
            .name("Credential name")
            .locale("sv")
            .logo(new Display.Image("https://example.com/logo", "Logo"))
            .description("Description")
            .backgroundColor("#000000")
            .backgroundImage(new Display.Image("https://example.com/background-image"))
            .textColor("#FFFFFF")
            .build()))
        .doctype("org.iso.18013.5.1.mDL")
        .claim("org.iso.18013.5.1","given_name", Claim.builder()
          .mandatory(true)
          .valueType("text")
          .display(List.of(
            Display.builder()
            .name("Given Name")
            .locale("en")
            .build(),
            Display.builder()
            .name("Förnamn")
            .locale("sv")
            .build()
            ))
          .build())
        .claim("org.iso.18013.5.1","family_name", Claim.builder()
          .mandatory(true)
          .valueType("text")
          .display(List.of(
            Display.builder()
            .name("Surname")
            .locale("en")
            .build(),
            Display.builder()
            .name("Efternamn")
            .locale("sv")
            .build()
            ))
          .build())
        .claim("org.iso.18013.5.1.aamva", "organ_donor", new Claim())
        .order(List.of("given_name","family_name"))
        .build())
      .build();

    log.info("ISO mDL Credential Issuer Metadata: \n{}", credentialIssuerMetadata.toJson(true));
  }

  @Test
  void testJsonLdCredentialIssuerMetadata() throws Exception {

    CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
      .credentialIssuer("https://example.com/credential-issuer")
      .authorizationServers(List.of("https://example.com/as-server"))
      .credentialEndpoint("https://example.com/credential-endpoint")
      .deferredCredentialEndpoint("https://example.com/deferred-credential-endpoint")
      .notificationEndpoint("https://example.com/notification-endpoint")
      .credentialResponseEncryption(CredentialResponseEncryption.builder()
        .algValuesSupported(List.of("RS256", "ES256"))
        .encValuesSupported(List.of("algo1", "algo2"))
        .encryptionRequired(false)
        .build())
      .batchCredentialIssuance(new BatchCredentialIssuance(100))
      .signedMetadata("signed_metadata_jwt")
      .display(List.of(Display.builder()
        .name("Credential Issuer Name")
        .locale("en")
        .logo(new Display.Image("https://example.com/logo", "Logo"))
        .build()))
      .credentialConfiguration("UniversityDegree_LDP_VC", JsonLdCredentialConfiguration.builder()
        .format("ldp_vc")
        .scope("UniversityDegree_LDP_VC")
        .cryptographicBindingMethodsSupported(List.of("binding1", "binding2"))
        .credentialSigningAlgValuesSupported(List.of("RS256", "ES256"))
        .proofType("jwt", new AbstractCredentialConfiguration.ProofType(List.of("ES256")))
        .display(List.of(
          Display.builder()
            .name("Credential name")
            .locale("sv")
            .logo(new Display.Image("https://example.com/logo", "Logo"))
            .description("Description")
            .backgroundColor("#000000")
            .backgroundImage(new Display.Image("https://example.com/background-image"))
            .textColor("#FFFFFF")
            .build()))
        .credentialDefinition(JsonLdCredentialConfiguration.JsonLdCredentialDefinition.builder()
          .context(List.of("https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"))
          .type(List.of("VerifiableCredential","UniversityDegreeCredential"))
          .credentialSubjectClaim("given_name", Claim.builder()
            .mandatory(true)
            .valueType("text")
            .display(List.of(
              Display.builder()
                .name("Given Name")
                .locale("en")
                .build(),
              Display.builder()
                .name("Förnamn")
                .locale("sv")
                .build()
            ))
            .build())
          .credentialSubjectClaim("family_name", Claim.builder()
            .mandatory(true)
            .valueType("text")
            .display(List.of(
              Display.builder()
                .name("Surname")
                .locale("en")
                .build(),
              Display.builder()
                .name("Efternamn")
                .locale("sv")
                .build()
            ))
            .build())
          .build())
        .order(List.of("given_name", "family_name"))
        .build())
      .build();

    log.info("JSON-LD Credential Issuer Metadata: \n{}", credentialIssuerMetadata.toJson(true));
  }
}