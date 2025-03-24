package se.oidc.oidfed.md.wallet.credentialissuer;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Description
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Display {

  @JsonProperty("name")
  private String name;

  @JsonProperty("locale")
  private String locale;

  @JsonProperty("logo")
  private Image logo;

  @JsonProperty("description")
  private String description;

  @JsonProperty("background_color")
  private String backgroundColor;

  @JsonProperty("background_image")
  private Image backgroundImage;

  @JsonProperty("text_color")
  private String textColor;

  @Data
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class Image {

    @JsonProperty("uri")
    private String uri;

    @JsonProperty("alt_text")
    private String altText;

    public Image(String uri) {
      this.uri = uri;
    }

    public Image(String uri, String altText) {
      this.uri = uri;
      this.altText = altText;
    }
  }

}
