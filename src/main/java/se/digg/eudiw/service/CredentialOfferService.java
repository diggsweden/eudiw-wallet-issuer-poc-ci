package se.digg.eudiw.service;

import se.digg.eudiw.model.credentialissuer.CredentialOfferParam;
import se.digg.eudiw.model.credentialissuer.PendingPreAuthorization;

import java.util.List;

public interface CredentialOfferService {
    CredentialOfferParam credentialOffer(String credentialOfferId);
    void store(String credentialOfferId, CredentialOfferParam credentialOffer);

    List<String> selectedCredentials(String selectedCredentialsId);
    void store(String selectedCredentialsId, List<String> selectedCredentials);

    void store(String preAuthCode, PendingPreAuthorization pendingPreAuthorization);
    PendingPreAuthorization pendingPreAuthorization(String preAuthCode);
}
