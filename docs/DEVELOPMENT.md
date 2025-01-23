# Development Guide Lines

## Signer certificate

JWTs are signed with a private key.

Generate key
```shell
openssl ecparam -genkey -name prime256v1 -noout -out issuer-jwt-ec256-key-pair.pem
```

Generate corresponding public key
```shell
openssl ec -in issuer-jwt-ec256-key-pair.pem -pubout -out issuer-jwt-ec256-public-key.pem
```

Self signed certificate public key
```shell
openssl req -new -x509 -key issuer-jwt-ec256-key-pair.pem -out issuer-jwt-ec256-public-key.crt -days 360

```

Make sure application.properties in the active profile has proper key pair config
```shell
eudiw.issuerSignerKeyPemFile: issuer-jwt-ec256-key-pair.pem
```
or set it with environment variable `EUDIW_ISSUER_SIGNER_KEY_PEM_FILE=issuer-jwt-ec256-key-pair.pem`

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

Currently, a few of the projects mvn package deps is hosted on GitHub.
GitHub's mvn repo needs an access token even on public packages.
Configure the 'development/maven-gh-settings.xml' and set your GitHub-access token there.

```shell
mvn -s development/maven-gh-settings.xml clean verify
```

## VSCode

Go to Preferences > Settings > Workspace
Search 'maven'
Set 'Java > Configuration > Maven: User Settings' to development/maven-gh-settings.xml to make VSCode use the local settings

## Tag and Release a new version

Activate the GH-workflow with a tag and push

Example:

```shell
git tag -s v0.0.32 -m 'v0.0.32'
git push origin 
```

(Currently a gh-workflow and image release flow with act on Tag pushes.
It sets the Pom-version, generates a changelog,  

## Run same code quality test locally as in CI

```shell
./developement/codequality.sh
```
