package se.digg.eudiw.model.credentialissuer;

import java.util.List;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;


@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class CredentialOfferParam {

    String credentialIssuer;
    List<String> credentials;
    Grants grants;

    public CredentialOfferParam(String credentialIssuer, List<String> credentials) {
        this.credentialIssuer = credentialIssuer;
        this.credentials = credentials;
    }

    public String getCredentialIssuer() {
        return credentialIssuer;
    }

    public void setCredentialIssuer(String credentialIssuer) {
        this.credentialIssuer = credentialIssuer;
    }

    public List<String> getCredentials() {
        return credentials;
    }   

    public void setCredentials(List<String> credentials) {
        this.credentials = credentials;
    }

    public Grants getGrants() {
        return grants;
    }

    public void setGrants(Grants grants) {
        this.grants = grants;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((credentialIssuer == null) ? 0 : credentialIssuer.hashCode());
        result = prime * result + ((credentials == null) ? 0 : credentials.hashCode());
        result = prime * result + ((grants == null) ? 0 : grants.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CredentialOfferParam other = (CredentialOfferParam) obj;
        if (credentialIssuer == null) {
            if (other.credentialIssuer != null)
                return false;
        } else if (!credentialIssuer.equals(other.credentialIssuer))
            return false;
        if (credentials == null) {
            if (other.credentials != null)
                return false;
        } else if (!credentials.equals(other.credentials))
            return false;
        if (grants == null) {
            if (other.grants != null)
                return false;
        } else if (!grants.equals(other.grants))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "CredentialOfferParam [credentialIssuer=" + credentialIssuer + ", credentials=" + credentials
                + ", grants=" + grants + "]";
    }

}
