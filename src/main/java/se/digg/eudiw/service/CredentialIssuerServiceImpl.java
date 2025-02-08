package se.digg.eudiw.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.model.credentialissuer.CredentialFormatEnum;
import se.digg.wallet.datatypes.common.*;
import se.digg.wallet.datatypes.mdl.process.MdlTokenIssuer;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtTokenInput;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtTokenIssuer;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class CredentialIssuerServiceImpl implements CredentialIssuerService {

    private static final Logger logger = LoggerFactory.getLogger(CredentialIssuerServiceImpl.class);

    private final EudiwConfig eudiwConfig;

    final PkiCredential issuerCredential;

    public CredentialIssuerServiceImpl(@Autowired EudiwConfig eudiwConfig, @Autowired CredentialBundles credentialBundles) {
        this.eudiwConfig = eudiwConfig;
        issuerCredential = credentialBundles.getCredential("issuercredential");
    }

    @Override
    public String credential(CredentialFormatEnum reqFormat, String credentialType, JWK deviceProofPublicKey, Jwt jwt) throws TokenIssuingException {
        switch (reqFormat) {
            case VC_SD_JWT -> {
                return sdJwtVcCredential(credentialType, deviceProofPublicKey, jwt);
            }
            case MSO_MDOC -> {
                return msoMdocCredential(credentialType, deviceProofPublicKey, jwt);
            }
        }
        return null;
    }

    private String sdJwtVcCredential(String credentialType, JWK deviceProofPublicKey, Jwt jwt) throws TokenIssuingException {
        TokenIssuer<SdJwtTokenInput> tokenIssuer = new SdJwtTokenIssuer();
        SdJwtTokenInput sdJwtTokenInput = new SdJwtTokenInput();
        sdJwtTokenInput.setIssuer(eudiwConfig.getIssuer());
        sdJwtTokenInput.setVerifiableCredentialType(credentialType);
        sdJwtTokenInput.setAlgorithm(TokenSigningAlgorithm.ECDSA_256);
        sdJwtTokenInput.setIssuerCredential(issuerCredential);
        sdJwtTokenInput.setWalletPublicKey(issuerCredential.getPublicKey());
        sdJwtTokenInput.setAttributes(Stream.of(
                TokenAttribute.builder().type(new TokenAttributeType("given_name")).value(jwt.getClaim("givenName")).build(),
                TokenAttribute.builder().type(new TokenAttributeType("last_name")).value(jwt.getClaim("surname")).build(),
                TokenAttribute.builder().type(new TokenAttributeType("issuance_date")).value(new Date()).build(),
                TokenAttribute.builder().type(new TokenAttributeType("age_over_18")).value(Boolean.TRUE).build(),
                TokenAttribute.builder().type(new TokenAttributeType("issuing_country")).value("SE").build(),
                TokenAttribute.builder().type(new TokenAttributeType("issuing_authority")).value("DIGG").build(),
                TokenAttribute.builder().type(new TokenAttributeType("birth_date")).value("19121212").build(),
                TokenAttribute.builder().type(new TokenAttributeType("expiry_date")).value(Instant.now().plus(Duration.ofHours(eudiwConfig.getExpHours()))).build() // TODO


        ).filter(item -> item.getValue() != null).toList());
        sdJwtTokenInput.setExpirationDuration(Duration.ofHours(eudiwConfig.getExpHours()));


        try {
            sdJwtTokenInput.setWalletPublicKey(deviceProofPublicKey.toECKey().toECPublicKey());
        } catch (JOSEException e) {
            logger.error("Could not issue pid without proof", e);
            throw new TokenIssuingException("Could not issue pid without proof");
        }

        String pidJwtToken = new String(tokenIssuer.issueToken(sdJwtTokenInput));
        logger.info("issue pid jwt token {}", pidJwtToken);

        return pidJwtToken;
    }

    private String msoMdocCredential(String credentialType, JWK deviceProofPublicKey, Jwt jwt) throws TokenIssuingException {

        List<TokenAttribute> tokenAttributes = List.of(
                TokenAttribute.builder()
                        .type(new TokenAttributeType(
                                TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
                                "issuing_country"))
                        .value("SE")
                        .build(),
                TokenAttribute.builder()
                        .type(new TokenAttributeType(
                                TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
                                "given_name")).value(jwt.getClaim("givenName")).build(),
                TokenAttribute.builder()
                        .type(new TokenAttributeType(
                                TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
                                "family_name")).value(jwt.getClaim("surname")).build(),
                TokenAttribute.builder()
                        .type(new TokenAttributeType(
                                TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
                                "birth_date")).value(jwt.getClaim("birthDate")).build(),
                TokenAttribute.builder()
                        .type(new TokenAttributeType(
                                TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
                                "issuance_date")).value(new Date()).build(),

                TokenAttribute.builder()
                        .type(new TokenAttributeType(
                                TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
                                "age_over_18"))
                        .value(true) // TODO
                        .build(),
                TokenAttribute.builder()
                        .type(new TokenAttributeType(
                                TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
                                "expiry_date"))
                        .value(LocalDate.ofInstant(Instant.now().plus(Duration.ofHours(eudiwConfig.getExpHours())), ZoneId.systemDefault()))
                        .build(),
                TokenAttribute.builder()
                        .type(new TokenAttributeType(
                                TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
                                "issuing_authority"))
                        .value("Test PID issuer")
                        .build()
        );

        TokenInput.TokenInputBuilder tokenInputBuilder = TokenInput.builder();
       try {
            PublicKey walletPublicKey = deviceProofPublicKey.toECKey().toECPublicKey();
            if (walletPublicKey != null)
                tokenInputBuilder.walletPublicKey(walletPublicKey);
            else
                throw new RuntimeException("wallet public key is not found");

        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        tokenInputBuilder.issuerCredential(issuerCredential);
        tokenInputBuilder.algorithm(TokenSigningAlgorithm.ECDSA_256);
        tokenInputBuilder.expirationDuration(Duration.ofHours(eudiwConfig.getExpHours()));
        tokenInputBuilder.attributes(tokenAttributes);

        TokenInput tokenInput = tokenInputBuilder.build();
        MdlTokenIssuer tokenIssuer = new MdlTokenIssuer(true);

        byte[] token = tokenIssuer.issueToken(tokenInput);
        String mdlToken = Base64.getEncoder().encodeToString(token);

        logger.info("mdl token {}", mdlToken);
        return mdlToken;
    }
}
