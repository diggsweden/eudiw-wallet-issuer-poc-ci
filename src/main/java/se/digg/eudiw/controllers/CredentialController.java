package se.digg.eudiw.controllers;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PostMapping;

import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.config.SignerConfig;
import se.digg.eudiw.credentialissuer.model.CredentialFormatEnum;
import se.digg.eudiw.service.OpenIdFederationService;
import se.digg.eudiw.credentialissuer.model.Address;
import se.digg.eudiw.credentialissuer.model.CredentialOfferParam;
import se.digg.eudiw.credentialissuer.model.CredentialParam;
import se.digg.eudiw.credentialissuer.util.PidBuilder;
import se.digg.wallet.datatypes.common.TokenAttribute;
import se.digg.wallet.datatypes.common.TokenInput;
import se.digg.wallet.datatypes.common.TokenIssuer;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;
import se.digg.wallet.datatypes.mdl.process.MdlTokenIssuer;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtTokenInput;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtTokenIssuer;
import se.oidc.oidfed.md.wallet.credentialissuer.WalletOAuthClientMetadata;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;

@RestController
public class CredentialController {

	private static final Logger logger = LoggerFactory.getLogger(CredentialController.class);

	private final EudiwConfig eudiwConfig;
	private final SignerConfig signerConfig;
	private final OpenIdFederationService openIdFederationService;
    private final CredentialBundles credentialBundles;

    public CredentialController(@Autowired EudiwConfig eudiwConfig, @Autowired OpenIdFederationService openIdFederationService, @Autowired SignerConfig signerConfig, @Autowired  CredentialBundles credentialBundles) {
		this.eudiwConfig = eudiwConfig;
		this.signerConfig = signerConfig;
		this.openIdFederationService = openIdFederationService;
        this.credentialBundles = credentialBundles;
    }

	@GetMapping("/demo-oidfed-client")
	String oidfedClientDemo() {
        try {
            return openIdFederationService.resolveWallet("1234567890").toJson(true);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

	@GetMapping("/demo-credential")
	String demoCredential() {
        try {
			return new PidBuilder(eudiwConfig.getIssuer(), signerConfig)
                        .withExp(eudiwConfig.getExpHours())
                        .withVcType("IdentityCredential")
                        .addSelectiveDisclosure("given_name", "John")
                        .addSelectiveDisclosure("address", new Address("123 Main St", "Anytown", "Anystate", "US"))
                        .build();
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
 
    }

    @PostMapping("/credential")
	String credential(@AuthenticationPrincipal Jwt jwt, @RequestBody CredentialParam credential) { // @AuthenticationPrincipal Jwt jwt,
		String pidJwtToken = null;
		try {

			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			if (authentication.getPrincipal() instanceof Jwt) {

				String clientId =  jwt.getClaim("clientId");
				WalletOAuthClientMetadata walletOAuthClientMetadata = openIdFederationService.resolveWallet(clientId);
				Optional<JWK> jwk;
				if (walletOAuthClientMetadata != null) {
					jwk = walletOAuthClientMetadata.getJwkSet().getKeys().stream().findFirst();
				}
				else {
					jwk = Optional.empty();
				}

				final PkiCredential issuerCredential = credentialBundles.getCredential("issuercredential");

				if (credential.getFormat() == CredentialFormatEnum.JWT_VC_JSON) {
					//PkiCredential issuerCredential = signerConfig.getCredential();
					TokenIssuer<SdJwtTokenInput> tokenIssuer = new SdJwtTokenIssuer();
					SdJwtTokenInput sdJwtTokenInput = new SdJwtTokenInput();
					sdJwtTokenInput.setIssuer(eudiwConfig.getIssuer());
					sdJwtTokenInput.setVerifiableCredentialType("https://attestations.eudiw.se/se_pid");
					sdJwtTokenInput.setAlgorithm(TokenSigningAlgorithm.ECDSA_256);
					sdJwtTokenInput.setIssuerCredential(issuerCredential);
					sdJwtTokenInput.setWalletPublicKey(issuerCredential.getPublicKey());
					sdJwtTokenInput.setAttributes(Stream.of(
							TokenAttribute.builder().name("given_name").value(jwt.getClaim("givenName")).build(),
							TokenAttribute.builder().name("last_name").value(jwt.getClaim("surname")).build(),
							TokenAttribute.builder().name("birthdate").value(jwt.getClaim("birthDate")).build(),
							TokenAttribute.builder().name("issuance_date").value(new Date()).build(),
							TokenAttribute.builder().name("age_over_18").value(Boolean.TRUE).build(),
							TokenAttribute.builder().name("issuing_country").value("SE").build(),
							TokenAttribute.builder().name("issuing_authority").value("DIGG").build(),
							TokenAttribute.builder().name("birth_date").value("19121212").build(),
							TokenAttribute.builder().name("expiry_date").value(Instant.now().plus(Duration.ofHours(eudiwConfig.getExpHours()))).build() // TODO


					).filter(item -> item.getValue() != null).collect(Collectors.toList()));
					sdJwtTokenInput.setExpirationDuration(Duration.ofHours(eudiwConfig.getExpHours()));
					jwk.ifPresent(value -> {
                        try {
                            sdJwtTokenInput.setWalletPublicKey(value.toECKey().toECPublicKey());
                        } catch (JOSEException e) {
                            throw new RuntimeException(e);
                        }
                    });
					pidJwtToken =  new String(tokenIssuer.issueToken(sdJwtTokenInput));
					logger.info("pid jwt token {}", pidJwtToken);

					// TODO - get PID data from ID token and authentic source (t.ex. skatteverket)
					//return pidJwtToken;
				}
/* mdl
				final String pidNameSpace = "eu.europa.ec.eudi.pid.1";
				final String mdlNameSpace = "org.iso.18013.5.1";

				List<TokenAttribute> tokenAttributes = List.of(
						TokenAttribute.builder()
								.nameSpace(pidNameSpace)
								.name("issuing_country")
								.value("SE")
								.build(),
						TokenAttribute.builder().nameSpace(pidNameSpace).name("given_name").value(jwt.getClaim("givenName")).build(),
						TokenAttribute.builder().nameSpace(pidNameSpace).name("family_name").value(jwt.getClaim("surname")).build(),
						TokenAttribute.builder().nameSpace(pidNameSpace).name("birth_date").value(jwt.getClaim("birthDate")).build(),
						TokenAttribute.builder()
								.nameSpace(pidNameSpace)
								.name("age_over_18")
								.value(true) // TODO
								.build(),
						TokenAttribute.builder()
								.nameSpace(pidNameSpace)
								.name("expiry_date")
								.value(LocalDate.ofInstant(Instant.now().plus(Duration.ofHours(eudiwConfig.getExpHours())), ZoneId.systemDefault()))
								.build(),
						TokenAttribute.builder()
								.nameSpace(pidNameSpace)
								.name("issuing_authority")
								.value("Test PID issuer")
								.build()
				);

				TokenInput.TokenInputBuilder tokenInputBuilder = TokenInput.builder();
				jwk.ifPresent(value -> {
					try {
						PublicKey walletPublicKey = value.toECKey().toECPublicKey();
						if (walletPublicKey != null)
							tokenInputBuilder.walletPublicKey(walletPublicKey);
						else
							throw new RuntimeException("wallet public key is not found");

					} catch (JOSEException e) {
						throw new RuntimeException(e);
					}
				});

				tokenInputBuilder.issuerCredential(issuerCredential);
				tokenInputBuilder.algorithm(TokenSigningAlgorithm.ECDSA_256);
				tokenInputBuilder.expirationDuration(Duration.ofHours(eudiwConfig.getExpHours()));
				tokenInputBuilder.attributes(tokenAttributes);

				TokenInput tokenInput = tokenInputBuilder.build();
				MdlTokenIssuer tokenIssuer = new MdlTokenIssuer(true);

				byte[] token = tokenIssuer.issueToken(tokenInput);
				String mdlToken = Hex.toHexString(token);
				logger.info("mdl token {}", mdlToken);
				//return mdlToken;
*/
				return pidJwtToken;

				//builder.addSelectiveDisclosure("address", new Address("123 Main St", "Anytown", "Anystate", "US"));

				//jwk.ifPresent(value -> builder.withCnf(Map.of("jwk", value.toPublicJWK().toJSONObject())));

				//return builder.build();
			}
			
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
		return null;
    }


    @GetMapping("/credential_offer")
    Map<String, Object> credentialOffer(@RequestParam("credential_offer") CredentialOfferParam credentialOffer) {
        try {
			return Map.of("todo", "foobar");
		} catch(Exception e) {
			throw new RuntimeException(e);
		}

    }

}