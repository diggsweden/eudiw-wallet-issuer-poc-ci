package se.digg.eudiw.credentialissuer.util;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import se.digg.eudiw.credentialissuer.model.JwtProof;

import java.text.ParseException;
import java.util.Optional;

public class ProofDecoder {

    public static Optional<JWK> decodeJwtProf(JwtProof proof) {
        if (proof == null)  return Optional.empty();

        if (!"jwt".equals(proof.getProofType())) return  Optional.empty();

        if (proof.getJwt() == null)  return  Optional.empty();

        try {
            SignedJWT signedJWT = SignedJWT.parse(proof.getJwt());
            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();

            JWSHeader header = signedJWT.getHeader();
            JWK jwk = header.getJWK();

            if (jwk != null)  return  Optional.of(jwk);


        } catch (ParseException e) {
            return  Optional.empty();
        }

        return Optional.empty();
    }
}
