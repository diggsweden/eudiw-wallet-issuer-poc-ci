# Development Guide Lines

## Issuer signer certificate

Generate private key in PKCS#8 format
```
openssl genpkey -algorithm EC \
-pkeyopt ec_paramgen_curve:prime256v1 \
-out issuer_private_pkcs8.key
```

Extract public key
```
openssl pkey -in issuer_private_pkcs8.key -pubout -out issuer_public.key
```

Create self-signed certificate using PKCS#8 key
```
openssl req -new -x509 \
-key issuer_private_pkcs8.key \
-out issuer-certificate.crt \
-days 365 \
-subj "/CN=local.dev.swedenconnect.se" \
-addext "subjectAltName = DNS:local.dev.swedenconnect.se" \
-addext "keyUsage = Digital Signature"
```


Make sure application.properties in the active profile has proper key pair config
```yaml
credential:
  bundles:
    pem:
      issuercredential:
        private-key: file:./keystores/issuer_private_pkcs8.key
        certificates: file:./keystores/issuer-certificate.crt
        name: "Issuer credential"
  bundle:
    monitoring:
      health-endpoint-enabled: true
```

## Start the server

### command line

```shell
SPRING_PROFILES_ACTIVE=dev mvn spring-boot:run
```

### docker-compose

See [quick-start](../dev-environment/compose/quick-start.md)
```shell
cd dev-environment/compose
docker-compose --profile ewc up
```
The DemoTestsController can not run in compose.

## Build

<!-- Currently, a few of the projects mvn package deps is hosted on GitHub.
GitHub's mvn repo needs an access token even on public packages.
Configure the 'development/maven-gh-settings.xml' and set your GitHub-access token there. -->

```shell
mvn clean verify
```

## VSCode

<!-- Go to Preferences > Settings > Workspace
Search 'maven'
Set 'Java > Configuration > Maven: User Settings' to development/maven-gh-settings.xml to make VSCode use the local settings -->

## Tag and Release a new version

Activate the GH-workflow with a tag and push

Example:

```shell
git tag -s v0.0.32 -m 'v0.0.32'
git push origin tag v0.0.32
```

(Currently a gh-workflow and image release flow with act on Tag pushes.
It sets the Pom-version, generates a changelog,  

## Run same code quality test locally as in CI

```shell
./developement/codequality.sh
```
