package se.digg.eudiw.service;

import se.digg.eudiw.model.credentialissuer.CredentialOfferParam;
import se.digg.eudiw.model.credentialissuer.PendingPreAuthorization;

public interface CredentialOfferService {
    CredentialOfferParam credentialOffer(String credentialOfferId);
    void store(String credentialOfferId, CredentialOfferParam credentialOffer);

    void store(String preAuthCode, PendingPreAuthorization pendingPreAuthorization);

    PendingPreAuthorization pendingPreAuthorization(String preAuthCode);
}
