package se.digg.eudiw.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageConfig;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.ModelAndView;
import se.digg.eudiw.authentication.SwedenConnectPrincipal;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.model.credentialissuer.CredentialOfferParam;
import se.digg.eudiw.model.credentialissuer.PendingPreAuthorization;
import se.digg.eudiw.model.credentialissuer.TxCodeInputMode;
import se.digg.eudiw.model.credentialissuer.TxCodeType;
import se.digg.eudiw.service.CredentialOfferService;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Controller
@SessionAttributes("codeVerifier")
public class PidPreAuthCredentialOfferController {
    private final CredentialOfferService credentialOfferService;
    Logger logger = LoggerFactory.getLogger(PidPreAuthCredentialOfferController.class);

    final URI callbackUri;
    final URI authzEndpoint;
    final URI tokenEndpoint;

    Nonce nonce = new Nonce(); // move to request
    Random rnd;

	private EudiwConfig eudiwConfig;

    PidPreAuthCredentialOfferController(@Autowired EudiwConfig eudiwConfig, @Autowired CredentialOfferService credentialOfferService) {
        logger.info("PreAuthController created");
        this.eudiwConfig = eudiwConfig;

        callbackUri = URI.create(String.format("%s/pid/preauth", eudiwConfig.getIssuerBaseUrl()));
        authzEndpoint = URI.create(String.format("%s/oauth2/authorize", eudiwConfig.getIssuerBaseUrl()));
        tokenEndpoint = URI.create(String.format("%s/oauth2/token", eudiwConfig.getIssuerBaseUrl()));
        this.credentialOfferService = credentialOfferService;

        rnd = new Random();
    }

    /**
     * Initialize auth in pre-auth flow
     * @return
     * @throws URISyntaxException
     */
    @GetMapping("/pid/preauth")
    public ModelAndView initPreAuthPid(@ModelAttribute("codeVerifier") CodeVerifier pkceVerifier, @RequestParam("code") Optional<String> codeParam, @RequestParam("state") Optional<String> state, Model model) throws URISyntaxException {

        if (codeParam.isEmpty() || codeParam.get().isEmpty()) {
            // Generate new random string to link the callback to the authZ request
            State newState = new State();

            Scope scope = new Scope();
            scope.add("eu.europa.ec.eudi.pid.1");
            scope.add("openid");



            AuthenticationRequest request = new AuthenticationRequest.Builder(
                    new ResponseType("code"),
                    scope,
                    new ClientID(eudiwConfig.getClientId()),
                    callbackUri)
                    .endpointURI(authzEndpoint)
                    .state(newState)
                    .nonce(nonce)
                    .codeChallenge(pkceVerifier, CodeChallengeMethod.S256)
                    .build();

            //String redirectUri = request.toURI().toString();
            Map<String, List<String>> params = request.toParameters();
            URI redirectUri = request.getEndpointURI();
            logger.info("Redirecting to: " + redirectUri);
            ModelMap modelMap = new ModelMap();
            modelMap.addAllAttributes(params);

            return new ModelAndView(String.format("redirect:%s", redirectUri), modelMap);
        }

        logger.info("code: {}", codeParam);

        AuthorizationCode code = new AuthorizationCode(codeParam.get());
        AuthorizationGrant codeGrant = new PreAuthCodeAuthorizationGrant(code, callbackUri, pkceVerifier);

        logger.info("codeGrant: {}", codeGrant.toParameters());

        ClientID clientID = new ClientID(eudiwConfig.getClientId());

        ModelAndView modelAndView = new ModelAndView("pid-pre-auth-credential-offer");

        QRCodeWriter qrCodeWriter = new QRCodeWriter();

        CredentialOfferParam credentialOfferParam = new CredentialOfferParam(eudiwConfig.getIssuer(), List.of("eu.europa.ec.eudi.pid_jwt_vc_json"));
        credentialOfferParam.setGrants(Map.of(se.digg.eudiw.model.credentialissuer.GrantType.PRE_AUTHORIZED_CODE, new se.digg.eudiw.model.credentialissuer.PreAuthorizationCodeGrant(codeParam.get(), eudiwConfig.getAuthHost(), new TxCodeType(TxCodeInputMode.NUMERIC, 6, "PIN"))));

        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        SwedenConnectPrincipal swedenConnectPrincipal = null;
        Object principal = authentication.getPrincipal();
        if (principal instanceof SwedenConnectPrincipal) {
            swedenConnectPrincipal = (SwedenConnectPrincipal) principal;
        }

        if (swedenConnectPrincipal == null) {
            throw new RuntimeException("TODO handle not authenticated");
        }

        int number = rnd.nextInt(999999);

        String txCode = String.format("%06d", number);
        PendingPreAuthorization pendingPreAuthorization = new PendingPreAuthorization(credentialOfferParam, callbackUri.toString(), pkceVerifier, clientID.getValue(), txCode, swedenConnectPrincipal);
        credentialOfferService.store(code.getValue(), pendingPreAuthorization);

        logger.info("Pending Credential offer: {}", pendingPreAuthorization);

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        String jsonData = null;
        try {

            jsonData = new ObjectMapper().writeValueAsString(credentialOfferParam);
            String uuid = UUID.randomUUID().toString();
            credentialOfferService.store(uuid, credentialOfferParam);


            //String credOffer = String.format("openid-credential-offer://credential_offer?credential_offer=%s", URLEncoder.encode(jsonData, StandardCharsets.UTF_8));
            String credentialUrl = String.format("%s/credential_offer/%s", eudiwConfig.getIssuerBaseUrl(), uuid);
            String credOffer = String.format("openid-credential-offer://credential_offer?credential_offer_uri=%s", URLEncoder.encode(credentialUrl, StandardCharsets.UTF_8));
            logger.info("Creating QR code for credential offer: {}", credOffer);
            BitMatrix bitMatrix = qrCodeWriter.encode(credOffer, BarcodeFormat.QR_CODE, 300, 300);

            ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
            MatrixToImageConfig con = new MatrixToImageConfig();

            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream,con);
            byte[] pngData = pngOutputStream.toByteArray();
            String qrCode = Base64.getEncoder().encodeToString(pngData);

            modelAndView.getModelMap().addAttribute("qrCode", String.format("data:image/jpeg;base64, %s", qrCode));
            modelAndView.getModelMap().addAttribute("linkUrl", credOffer);
            modelAndView.getModelMap().addAttribute("txCode", txCode);

            return modelAndView;
        } catch (WriterException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    @ModelAttribute("codeVerifier")
    public CodeVerifier codeVerifier() {
        return  new CodeVerifier();
    }


      protected static class PreAuthCodeAuthorizationGrant extends AuthorizationGrant {
          private final AuthorizationCode code;
          private final URI redirectURI;
          private final CodeVerifier pkceVerifier;
          private static final GrantType GRANT_TYPE = new GrantType("urn:ietf:params:oauth:grant-type:pre-authorized_code");

        PreAuthCodeAuthorizationGrant(AuthorizationCode code, URI redirectURI, CodeVerifier pkceVerifier) {
            super(GRANT_TYPE);
            this.code = code;
            this.redirectURI = redirectURI;
            this.pkceVerifier = pkceVerifier;
        }

        @Override
        public Map<String, List<String>> toParameters() {
            Map<String, List<String>> params = new LinkedHashMap();
            params.put("grant_type", Collections.singletonList(GRANT_TYPE.getValue()));
            params.put("pre-authorized_code", Collections.singletonList(this.code.getValue()));
            params.put("code", Collections.singletonList(this.code.getValue()));
            if (this.redirectURI != null) {
                params.put("redirect_uri", Collections.singletonList(this.redirectURI.toString()));
                params.put("code_verifier", List.of(pkceVerifier.getValue()));
            }

            return params;
        }
    }
}
