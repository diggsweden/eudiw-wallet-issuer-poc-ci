package se.digg.eudiw.service;

import org.springframework.data.redis.core.RedisOperations;
import org.springframework.stereotype.Service;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.model.credentialissuer.CredentialOfferParam;
import se.digg.eudiw.model.credentialissuer.PendingPreAuthorization;
import java.security.SecureRandom;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
public class CredentialOfferServiceImpl implements CredentialOfferService {

    private static final SecureRandom rng = new SecureRandom();

    private final RedisOperations<String, CredentialOfferParam> operations;
    private final RedisOperations<String, List<String>> selectedCredentialsRedisOperations;

    private final RedisOperations<String, PendingPreAuthorization> pendingPreAuthorizationRedisOperations;
    private final EudiwConfig eudiwConfig;

    public CredentialOfferServiceImpl(RedisOperations<String, CredentialOfferParam> operations, RedisOperations<String, List<String>> selectedCredentialsRedisOperations, RedisOperations<String, PendingPreAuthorization> pendingPreAuthorizationRedisOperations, EudiwConfig eudiwConfig) {
        this.operations = operations;
        this.selectedCredentialsRedisOperations = selectedCredentialsRedisOperations;
        this.eudiwConfig = eudiwConfig;
        this.pendingPreAuthorizationRedisOperations = pendingPreAuthorizationRedisOperations;
    }

    @Override
    public CredentialOfferParam credentialOffer(String credentialOfferId) {
        // TODO: change back to getAndDelete - temporary fix for android reference implementation wallet app
        return operations.opsForValue().get(credentialOfferId);
    }

    @Override
    public void store(String credentialOfferId, CredentialOfferParam credentialOffer) {
        operations.opsForValue().set(credentialOfferId, credentialOffer, eudiwConfig.getCredentialOfferTtlInSeconds(), TimeUnit.SECONDS);
    }

    @Override
    public List<String> selectedCredentials(String selectedCredentialsId) {
        return selectedCredentialsRedisOperations.opsForValue().getAndDelete(selectedCredentialsId);
    }

    @Override
    public void store(String selectedCredentialsId, List<String> selectedCredentials) {
        selectedCredentialsRedisOperations.opsForValue().set(selectedCredentialsId, selectedCredentials, eudiwConfig.getCredentialOfferTtlInSeconds(), TimeUnit.SECONDS);
    }

    @Override
    public void store(String preAuthCode, PendingPreAuthorization pendingPreAuthorization) {
        pendingPreAuthorizationRedisOperations.opsForValue().set(preAuthCode, pendingPreAuthorization, eudiwConfig.getCredentialOfferTtlInSeconds(), TimeUnit.SECONDS);
    }

    @Override
    public PendingPreAuthorization pendingPreAuthorization(String preAuthCode) {
        return pendingPreAuthorizationRedisOperations.opsForValue().getAndDelete(preAuthCode);
    }

}
