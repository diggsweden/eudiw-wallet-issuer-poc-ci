# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] - 2025-10-03

### Fixed

- Test gh sbom gen

## [0.4.0] - 2025-10-03

### Fixed

- Create devlfow attribs
- Create sha 256 only


## [3.18] - 2025-10-02

### Added

- Add dev flow

## [0.3.17] - 2025-10-02

### Added

- Add testors
- Add testors

### Fixed

- Summary test


## [0.3.14] - 2025-10-02

### Added

- Add testor


## [0.3.12] - 2025-10-02

### Added

- Add testor

## [0.3.11] - 2025-10-02

### Added

- Add testor

## [0.3.10] - 2025-10-02

### Added

- Add testor


## [0.3.9] - 2025-10-02

### Added

- Add testor


## [0.3.8] - 2025-10-02

### Added

- Add readme test

## [0.3.4] - 2025-10-02

### Added

- Add release flow refactor
- Add release flow perm
- Add release flow
- Add optional personal_administrative_number to sdjwt pid
- Add support for credential_configuration_id parameter in credential endpoint
- Add support for list of credentials in credential end-point
- Add versionnumbers to gh actions
- Add versionnumbers to gh actions
- Add versionnumbers to gh actions
- Add proxy config for rest client
- Add ewc itb issuer endpoints
- Add link to tokenlib at frontpage
- Add par metadata
- Add correct selected credentials to pre-auth credential offer
- Add new work-around for android ref impl wallet app
- Add work-around for android ref impl wallet app
- Add funded by eu logo asset
- Add funded by eu logo to site and some text fixes
- Add refactored credential offer
- Add content to information page
- Add digg logo and branding in issuer metadata
- Add code in project as temp work-around mvn deps
- Add pre-auth credential offer support
- Add correct birth_date and age_in_years age_over_nn based on birth_date
- Add issuer state in auth code credential offer
- Add valkey as cache, credential offer wip and static front page
- Add cwt proof metadata
- Add code_key supported in metadata
- Add mso mdoc proof support
- Add token lib source code as temporary work-around
- Add par metadata in well-known
- Add mso mdoc support
- Add missing mdl metadata
- Add mdl eu.europa.ec.eudi.pid_mdoc - work in progress
- Add scope eu.europa.ec.eudi.pid.1 support
- Add refresh of main branch
- Add tok for bot
- Add work-around in order to handle a bug in openapi gen lib when multiple Accept types
- Add mvn build deps and fix test application.yml
- Add maven package repository for poc lib
- Add mvn support (#21)
- Add par authorization endpoint
- Add pre-auth code flow"
- Add working oidfed metadata and wip add jwk to issued credential
- Add cert instruction
- Add openid-federation and improve openid-credential-issuer metadata
- Add oid federation rest client
- Add ci,image,renovate,etc

### Changed

- Update dependency org.openapitools:openapi-generator-maven-plugin to v7.16.0 (#185)
- Update orhun/git-cliff-action action to v4.6.0 (#183)
- Update dependency org.apache.maven.plugins:maven-javadoc-plugin to v3.12.0 (#182)
- Update maven-plugins to v3.5.4 (#176)
- Update step-security/harden-runner action to v2.13.1 (#174)
- Update vct and type to latest specification
- Update dependency org.jreleaser:jreleaser-maven-plugin to v1.20.0 (#164)
- Update to follow Draft 15 of OID4VCI (#150)
- Update dependency org.openapitools:openapi-generator-maven-plugin to v7.15.0 (#159)
- Update github actions
- Update github actions to v5 (major)
- Extend descriptionlength for commitlint
- Update maven-plugins (#144)
- Update dependency org.jreleaser:jreleaser-maven-plugin to v1.19.0 (#142)
- Disable ewc itb automatic cookie management for rest client
- Skip consent page for pid issuance
- Update docker/build-push-action digest to 1dc7386 (#123)
- Update cgr.dev/chainguard/jre:latest docker digest to c4e0225 (#109)
- Disable redirect uri verification
- Update github actions (#106)
- Update maven-plugins to v3.5.3 (#107)
- Clean up oidc sweden dependencies
- Html fixes and a fix in the proof work around
- Update github actions
- Update cgr.dev/chainguard/jre:latest docker digest to 47f8c0e
- Update maven-plugins
- Use snapshots from central
- Change encoding of mso mdoc credential to base64 url encoded
- Bump token lib files
- Replace token lib
- Quick and dirty fix _sd_alg lowercase in order to test with refimpl app
- Update cgr.dev/chainguard/jre:latest docker digest to 35d28ee
- Use org wide shared components
- Correct typ in jwt header when sd jwt vc
- Correct credential response exkl nonce
- Update dependency org.apache.maven.plugins:maven-gpg-plugin to v3
- Upgrade nimbus dependencies
- Update maven-plugins
- Update github actions
- Merge branch 'renovate/cgr.dev-chainguard-jre-latest'
- Update cgr.dev/chainguard/jre:latest docker digest to 32f8e50
- Correct package info
- Generate pid with data-types and add dependencies as source code
- Restore releaseTmp note
- Restore jar artifact
- Update github actions
- Migrate renovate config
- Update orhun/git-cliff-action action to v4
- Group java deps
- Improve release flow
- Resolve wallet instance from oidfederation with clientid
- Update dependency org.apache.maven.plugins:maven-enforcer-plugin to v3.5.0
- Update dependency org.apache.maven.plugins:maven-failsafe-plugin to v3.5.2
- Update dependency org.apache.maven.plugins:maven-source-plugin to v3.3.1
- Update dependency org.apache.maven.plugins:maven-deploy-plugin to v3.1.3
- Update dependency org.apache.maven.plugins:maven-javadoc-plugin to v3.11.2
- Update dependency org.apache.maven.plugins:maven-surefire-plugin to v3.5.2
- Update dependency org.openapitools:openapi-generator-maven-plugin to v7.10.0
- Pin dependencies
- Update cgr.dev/chainguard/jre:latest docker digest to fba813a
- Improve workflows and friends
- Update cgr.dev/chainguard/jre:latest docker digest to fba813a
- Update plugin org.openapi.generator to v7.10.0
- Refactor, clean up, fix deprecated warnings
- Expose public jwk on endpoint and include kid in jwk
- Change configured host in dev profile to https://local.dev.swedenconnect.se:8443
- Chore: cleanup and add workflow.
- Initial commit

### Fixed

- Light weight
- Update dependency com.nimbusds:oauth2-oidc-sdk to v11.29.1 (#184)
- Update dependency org.apache.httpcomponents.core5:httpcore5 to v5.3.6 (#181)
- Update dependency org.springframework.boot:spring-boot-starter-parent to v3.5.6 (#180)
- Update dependency org.projectlombok:lombok to v1.18.42 (#179)
- Update dependency com.google.guava:guava to v33.5.0-jre (#178)
- Update java non-major to v1.82 (#177)
- Update java non-major to v2.0.7 (#175)
- Update dependency io.projectreactor:reactor-core to v3.7.11 (#173)
- Update dependency org.springdoc:springdoc-openapi-starter-webmvc-ui to v2.8.13 (#172)
- Update dependency com.nimbusds:nimbus-jose-jwt to v10.5 (#171)
- Update dependency org.projectlombok:lombok to v1.18.40 (#170)
- Update dependency io.lettuce:lettuce-core to v6.8.1.release (#168)
- Update dependency org.springdoc:springdoc-openapi-starter-webmvc-ui to v2.8.12 (#167)
- Update dependency com.nimbusds:oauth2-oidc-sdk to v11.28 (#163)
- Update java non-major (#162)
- Update dependency org.jsoup:jsoup to v1.21.2 (#160)
- Update spring non-major (#157)
- Update spring non-major (#137)
- Update nimbusds (#156)
- Update dependency io.projectreactor:reactor-core to v3.7.9 (#155)
- Update dependency io.lettuce:lettuce-core to v6.8.0.release (#153)
- Update dependency com.nimbusds:nimbus-jose-jwt to v10.4.1 (#152)
- Update dependency com.nimbusds:oauth2-oidc-sdk to v11.27 (#151)
- Update dependency com.nimbusds:oauth2-oidc-sdk to v11.26.1 (#149)
- Update dependency com.nimbusds:nimbus-jose-jwt to v10.4 (#148)
- Update dependency commons-io:commons-io to v2.20.0 (#147)
- Update java non-major to v2.19.2 (#146)
- Update dependency io.projectreactor:reactor-core to v3.7.8 (#145)
- Update dependency com.nimbusds:nimbus-jose-jwt to v10.3.1 (#143)
- Update java non-major (#138)
- Update dependency com.nimbusds:oauth2-oidc-sdk to v11.26 (#136)
- Update java non-major to v2.19.1 (#135)
- Update dependency io.projectreactor:reactor-core to v3.7.7 (#134)
- Update spring non-major (#130)
- Update java non-major (#133)
- Update dependency io.lettuce:lettuce-core to v6.7.0.release (#132)
- Update dependency com.nimbusds:oauth2-oidc-sdk to v11.25 (#129)
- Update dependency io.projectreactor:reactor-core to v3.7.6 (#122)
- Update nimbusds (#112)
- Update java non-major to v2.0.6 (#120)
- Update dev tools (#108)
- Update spring non-major (#100)
- Update java non-major (#99)
- Fix CI
- Correct eudiw ri credential status code when missing proof
- Fix birth date bug in credential
- Update nimbusds
- Update java non-major
- Update spring non-major to v6.2.5 (#98)
- Update spring non-major
- Fix another proof binding work-around
- Fix proof binding work-around
- Fix dependency issue
- Update spring non-major
- Update nimbusds
- Fix jar build for image
- Update dependency se.swedenconnect.security:credentials-support to v2
- Update java non-major
- Update dev tools
- Fix types in var
- Update dependency org.bouncycastle:bcprov-jdk18on to v1.80
- Correct typo
- Correct release vars
- Make test run with bogus cert
- Update spring non-major
- Fix linting issues
- Update zxing to v3.5.3
- Update spring non-major

### Removed

- Remove issues
- Remove gradle
- Remove hard coded urls (#55)


[0.4.1]: https://github.com/diggsweden/eudiw-wallet-issuer-poc-ci/compare/v0.4.0..v0.4.1
[0.4.0]: https://github.com/diggsweden/eudiw-wallet-issuer-poc-ci/compare/3.18..v0.4.0
[3.18]: https://github.com/diggsweden/eudiw-wallet-issuer-poc-ci/compare/v0.3.17..3.18
[0.3.17]: https://github.com/diggsweden/eudiw-wallet-issuer-poc-ci/compare/v0.3.14..v0.3.17
[0.3.14]: https://github.com/diggsweden/eudiw-wallet-issuer-poc-ci/compare/v0.3.12..v0.3.14
[0.3.12]: https://github.com/diggsweden/eudiw-wallet-issuer-poc-ci/compare/v0.3.11..v0.3.12
[0.3.11]: https://github.com/diggsweden/eudiw-wallet-issuer-poc-ci/compare/v0.3.10..v0.3.11
[0.3.10]: https://github.com/diggsweden/eudiw-wallet-issuer-poc-ci/compare/v0.3.9..v0.3.10
[0.3.9]: https://github.com/diggsweden/eudiw-wallet-issuer-poc-ci/compare/v0.3.8..v0.3.9
[0.3.8]: https://github.com/diggsweden/eudiw-wallet-issuer-poc-ci/compare/v0.3.4..v0.3.8

<!-- generated by git-cliff -->
