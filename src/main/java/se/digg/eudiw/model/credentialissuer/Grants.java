package se.digg.eudiw.model.credentialissuer;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class Grants {
    AuthorizationCode  authorizationCode;
    @JsonProperty("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    PreAuthorizedCode preAuthorizedCode;
}
