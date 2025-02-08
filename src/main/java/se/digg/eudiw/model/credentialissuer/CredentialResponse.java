package se.digg.eudiw.model.credentialissuer;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import java.util.Objects;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class CredentialResponse {
    private String credential;
    private String cNonce;
    private String cNonceExpiresIn;

    public CredentialResponse() {

    }

    public CredentialResponse(String credential) {
        this.credential = credential;
    }

    public CredentialResponse(String credential, String cNonce, String cNonceExpiresIn) {
        this.credential = credential;
        this.cNonce = cNonce;
        this.cNonceExpiresIn = cNonceExpiresIn;
    }

    public String getCredential() {
        return credential;
    }

    public void setCredential(String credential) {
        this.credential = credential;
    }

    public String getcNonce() {
        return cNonce;
    }

    public void setcNonce(String cNonce) {
        this.cNonce = cNonce;
    }

    public String getcNonceExpiresIn() {
        return cNonceExpiresIn;
    }

    public void setcNonceExpiresIn(String cNonceExpiresIn) {
        this.cNonceExpiresIn = cNonceExpiresIn;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        CredentialResponse that = (CredentialResponse) o;
        return Objects.equals(credential, that.credential) && Objects.equals(cNonce, that.cNonce) && Objects.equals(cNonceExpiresIn, that.cNonceExpiresIn);
    }

    @Override
    public int hashCode() {
        return Objects.hash(credential, cNonce, cNonceExpiresIn);
    }

    @Override
    public String toString() {
        return "CredentialResponse{" +
                "credential='" + credential + '\'' +
                ", cNonce='" + cNonce + '\'' +
                ", cNonceExpiresIn='" + cNonceExpiresIn + '\'' +
                '}';
    }
}

