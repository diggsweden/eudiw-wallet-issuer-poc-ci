package se.digg.eudiw.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.config.SignerConfig;
import se.digg.eudiw.service.OpenIdFederationService;
import se.oidc.oidfed.base.data.LanguageObject;
import se.oidc.oidfed.base.data.federation.EntityMetadataInfoClaim;
import se.oidc.oidfed.base.data.federation.EntityStatement;
import se.oidc.oidfed.base.data.federation.EntityStatementDefinedParams;
import se.oidc.oidfed.base.data.federation.TrustMarkClaim;
import se.oidc.oidfed.base.data.metadata.FederationEntityMetadata;
import se.oidc.oidfed.md.wallet.credentialissuer.*;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.nimbus.JwkTransformerFunction;

@RestController
public class MetadataController {


    private final OpenIdFederationService openIdFederationService;
    private final SignerConfig signer;
    private final EudiwConfig eudiwConfig;
    private final CredentialBundles credentialBundles;

    Logger logger = LoggerFactory.getLogger(MetadataController.class);

    public MetadataController(@Autowired EudiwConfig eudiwConfig, @Autowired OpenIdFederationService openIdFederationService, @Autowired SignerConfig signer, @Autowired CredentialBundles credentialBundles) {
        this.openIdFederationService = openIdFederationService;
        this.signer = signer;
        this.eudiwConfig = eudiwConfig;
        this.credentialBundles = credentialBundles;
    }

    @GetMapping("/.well-known/jwks.json")
    Map<String, Object> jwks() {
        final PkiCredential issuerCredential = credentialBundles.getCredential("issuercredential");
        return new JwkTransformerFunction().apply(issuerCredential).toJSONObject();
    }

    @GetMapping("/.well-known/openid-credential-issuer")
    CredentialIssuerMetadata metadata() {
        return CredentialIssuerMetadata.builder()
                .credentialIssuer(eudiwConfig.getIssuer())
                .authorizationServers(List.of(eudiwConfig.getAuthHost()))
                .credentialEndpoint(String.format("%s/credential", eudiwConfig.getCredentialHost()))
                .deferredCredentialEndpoint(String.format("%s/credential_deferred", eudiwConfig.getCredentialHost()))
                .notificationEndpoint(String.format("%s/notification", eudiwConfig.getCredentialHost()))
                //.batchCredentialIssuance(new BatchCredentialIssuance(100))
                .signedMetadata("signed_metadata_jwt")
                .display(List.of(
                        Display.builder()
                                .name("DIGG PID issuer")
                                .locale("en")
                                .build(),
                        Display.builder()
                                .name("DIGG PID utfärdare")
                                .locale("sv")
                                .build(),
                        Display.builder()
                                .name("DIGG PID aussteller")
                                .locale("de")
                                .build()
                ))
                .credentialConfiguration("VerifiablePortableDocumentA1", SdJwtCredentialConfiguration.builder()
                        .format("vc+sd-jwt")
                        .scope("VerifiablePortableDocumentA1")
                        .cryptographicBindingMethodsSupported(List.of("jwk"))
                        .credentialSigningAlgValuesSupported(List.of("ES256"))
                        .proofType("jwt", ProofTypeWrapper.createProofType(List.of("ES256")))                        
                        .display(List.of(
                                Display.builder()
                                        .name("DIGG PID")
                                        .locale("en")
                                        .build(),
                                Display.builder()
                                        .name("DIGG PID")
                                        .locale("sv")
                                        .build(),
                                Display.builder()
                                        .name("DIGG PID")
                                        .locale("de")
                                        .build()
                        ))
                        .vct("VerifiablePortableDocumentA1")
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
                                                .build(),
                                        Display.builder()
                                                .name("Vorname")
                                                .locale("de")
                                                .build()
                                ))
                                .build())
                        .claim("last_name", Claim.builder()
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
                                                .build(),
                                        Display.builder()
                                                .name("Nachname")
                                                .locale("de")
                                                .build()
                                ))
                                .build())
                        //.order(List.of("given_name","last_name"))
                        .build()
                )
                .credentialConfiguration("eu.europa.ec.eudi.pid_jwt_vc_json", SdJwtCredentialConfiguration.builder()
                        .format("vc+sd-jwt")
                        .scope("eu.europa.ec.eudi.pid.1")
                        .cryptographicBindingMethodsSupported(List.of("jwk"))
                        .credentialSigningAlgValuesSupported(List.of("ES256"))
                        .proofType("jwt", ProofTypeWrapper.createProofType(List.of("ES256")))
                        .display(List.of(
                                Display.builder()
                                        .name("DIGG PID")
                                        .locale("en")
                                        .build(),
                                Display.builder()
                                        .name("DIGG PID")
                                        .locale("sv")
                                        .build(),
                                Display.builder()
                                        .name("DIGG PID")
                                        .locale("de")
                                        .build()
                        ))
                        .vct("VerifiablePortableDocumentA1")
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
                                                .build(),
                                        Display.builder()
                                                .name("Vorname")
                                                .locale("de")
                                                .build()
                                ))
                                .build())
                        .claim("last_name", Claim.builder()
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
                                                .build(),
                                        Display.builder()
                                                .name("Nachname")
                                                .locale("de")
                                                .build()
                                ))
                                .build())
                        .claim("age_over_18", Claim.builder() // TODO kolla om det finns value type för boolean
                                .mandatory(true)
                                .display(List.of(
                                        Display.builder()
                                                .name("Adult or minor")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("birth_date", Claim.builder()
                                .mandatory(true)
                                .valueType("full-date") // TODO kolla hur det ska formateras
                                .display(List.of(
                                        Display.builder()
                                                .name("Date of Birth")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("expiry_date", Claim.builder()
                                .mandatory(true)
                                .valueType("full-date")
                                .display(List.of(
                                        Display.builder()
                                                .name("Expiry date")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("issuance_date", Claim.builder()
                                .mandatory(true)
                                .valueType("full-date")
                                .display(List.of(
                                        Display.builder()
                                                .name("Date (and possibly time) when the PID was issued")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("issuing_authority", Claim.builder()
                                .mandatory(true)
                                .valueType("text")
                                .display(List.of(
                                        Display.builder()
                                                .name("Name of the administrative authority that has issued this PID instance, or the ISO 3166 Alpha-2 country code of the respective Member State if there is no separate authority authorized to issue PIDs")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("issuing_country", Claim.builder()
                                .mandatory(true)
                                .valueType("text")
                                .display(List.of(
                                        Display.builder()
                                                .name("Alpha-2 country code, as defined in ISO 3166-1, of the PID Provider's country or territory")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        .claim("issuing_country", Claim.builder()
                                .mandatory(true)
                                .valueType("text")
                                .display(List.of(
                                        Display.builder()
                                                .name("Alpha-2 country code, as defined in ISO 3166-1, of the PID Provider's country or territory")
                                                .locale("en")
                                                .build()
                                ))
                                .build())
                        //.order(List.of("given_name","last_name"))
                        .build()
                )
                .build();
    }

    @RequestMapping(value = "/.well-known/openid-federation", produces = "application/TODO_ENTITY_STATEMENT_TYPE")
    public ResponseEntity<String> entityStatement() {
        Date now = new Date();
        Calendar issCalendar = Calendar.getInstance();
        issCalendar.setTime(now);
        Calendar expCalendar = Calendar.getInstance();
        expCalendar.setTime(issCalendar.getTime());
        expCalendar.add(Calendar.HOUR_OF_DAY, 24); // todo config

        final PkiCredential issuerCredential = credentialBundles.getCredential("issuercredential");

        try {
            final EntityStatementDefinedParams definedParams =
                    EntityStatementDefinedParams.builder()
                    .jwkSet(new JWKSet(signer.getPublicJwk()))
                    .metadata(
                            EntityMetadataInfoClaim.builder()
                            .federationEntityMetadataObject(
                                    FederationEntityMetadata.builder()
                                            .organizationName(LanguageObject.builder(String.class).defaultValue("DIGG").build())
                                            .build().toJsonObject())
                                    .customEntityMetadataObject("openid_credential_issuer", metadata().toJsonObject())
                                    .build()
                    )
                            .sourceEndpoint(String.format("%s/%s", eudiwConfig.getIssuerBaseUrl(), ".well-known/openid-federation"))
                            .authorityHints(eudiwConfig.getOpenidFederation().authorityHints())
                            .trustMarks(List.of(TrustMarkClaim.builder()
                                            .id(eudiwConfig.getOpenidFederation().trustMarkId())
                                            .trustMark(openIdFederationService.trustMark(eudiwConfig.getOpenidFederation().trustMarkId(), eudiwConfig.getOpenidFederation().subject()))
                                    .build()))
                            .build();

            String jwt = EntityStatement.builder()
                    .issuer(eudiwConfig.getIssuer())
                    .subject(eudiwConfig.getIssuer())
                    .issueTime(issCalendar.getTime())
                    .expriationTime(expCalendar.getTime())
                    .definedParams(definedParams)
                    .build(signer.getJwtSigningCredential(), null).getSignedJWT().serialize();

            return ResponseEntity.ok().body(jwt);
        } catch (JsonProcessingException | NoSuchAlgorithmException | JOSEException e) {
            logger.error("Could not create entity statement", e);
            return ResponseEntity.internalServerError().body("Could not create entity statement");
        }
    }
    private static class ProofTypeWrapper extends AbstractCredentialConfiguration {
        public static ProofType createProofType(List<String> algValues) {
                return new ProofType(algValues);
        }
        }
}
