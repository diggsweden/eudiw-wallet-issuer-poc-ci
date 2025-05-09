# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.18] - 2025-05-09

### Added

- Add correct selected credentials to pre-auth credential offer
- Add new work-around for android ref impl wallet app
- Add work-around for android ref impl wallet app
- Add funded by eu logo asset
- Add funded by eu logo to site and some text fixes

### Changed

- Update github actions (#106)
- Update maven-plugins to v3.5.3 (#107)

### Fixed

- Update java non-major to v2.0.6 (#120)
- Update dev tools (#108)
- Update spring non-major (#100)
- Update java non-major (#99)
- Fix CI
- Correct eudiw ri credential status code when missing proof

## [0.0.17] - 2025-04-24

### Added

- Add refactored credential offer
- Add content to information page
- Add digg logo and branding in issuer metadata
- Add code in project as temp work-around mvn deps
- Add pre-auth credential offer support

### Changed

- Clean up oidc sweden dependencies
- Html fixes and a fix in the proof work around
- Update github actions
- Update cgr.dev/chainguard/jre:latest docker digest to 47f8c0e
- Update maven-plugins

### Fixed

- Fix birth date bug in credential
- Update nimbusds
- Update java non-major
- Update spring non-major to v6.2.5 (#98)


## [0.0.15] - 2025-03-19

### Added

- Add correct birth_date and age_in_years age_over_nn based on birth_date
- Add issuer state in auth code credential offer

### Fixed

- Update spring non-major


## [0.0.15-diggdev] - 2025-03-10

### Added

- Add valkey as cache, credential offer wip and static front page
- Add cwt proof metadata
- Add code_key supported in metadata
- Add mso mdoc proof support
- Add token lib source code as temporary work-around
- Add par metadata in well-known

### Changed

- Use snapshots from central
- Change encoding of mso mdoc credential to base64 url encoded
- Bump token lib files
- Replace token lib
- Quick and dirty fix _sd_alg lowercase in order to test with refimpl app
- Update cgr.dev/chainguard/jre:latest docker digest to 35d28ee

### Fixed

- Fix another proof binding work-around
- Fix proof binding work-around
- Fix dependency issue
- Update spring non-major
- Update nimbusds

## [0.0.14] - 2025-02-03

### Fixed

- Fix jar build for image


## [0.0.13] - 2025-02-03

### Changed

- Use org wide shared components
- Correct typ in jwt header when sd jwt vc
- Correct credential response exkl nonce


## [0.0.12] - 2025-01-30

### Added

- Add mso mdoc support
- Add missing mdl metadata
- Add mdl eu.europa.ec.eudi.pid_mdoc - work in progress
- Add scope eu.europa.ec.eudi.pid.1 support


## [0.0.11] - 2025-01-29

### Changed

- Update dependency org.apache.maven.plugins:maven-gpg-plugin to v3
- Upgrade nimbus dependencies
- Update maven-plugins
- Update github actions
- Merge branch 'renovate/cgr.dev-chainguard-jre-latest'
- Update cgr.dev/chainguard/jre:latest docker digest to 32f8e50

### Fixed

- Update dependency se.swedenconnect.security:credentials-support to v2
- Update java non-major
- Update dev tools


## [0.0.10] - 2025-01-28

### Changed

- Correct package info
- Generate pid with data-types and add dependencies as source code


## [0.0.9] - 2025-01-23

### Changed

- Restore releaseTmp note
- Restore jar artifact
- Update github actions
- Migrate renovate config
- Update orhun/git-cliff-action action to v4
- Group java deps
- Improve release flow

### Removed

- Remove gradle


## [0.0.8] - 2025-01-23

### Removed

- Remove hard coded urls (#55)


## [0.0.7] - 2025-01-18

### Added

- Add refresh of main branch


## [0.0.6] - 2025-01-18

### Added

- Add tok for bot


## [0.0.5] - 2025-01-16

### Changed

- Resolve wallet instance from oidfederation with clientid


## [0.0.4] - 2025-01-16

### Fixed

- Fix types in var


## [0.0.3] - 2025-01-15

### Changed

- Update dependency org.apache.maven.plugins:maven-enforcer-plugin to v3.5.0
- Update dependency org.apache.maven.plugins:maven-failsafe-plugin to v3.5.2
- Update dependency org.apache.maven.plugins:maven-source-plugin to v3.3.1
- Update dependency org.apache.maven.plugins:maven-deploy-plugin to v3.1.3
- Update dependency org.apache.maven.plugins:maven-javadoc-plugin to v3.11.2
- Update dependency org.apache.maven.plugins:maven-surefire-plugin to v3.5.2
- Update dependency org.openapitools:openapi-generator-maven-plugin to v7.10.0
- Pin dependencies
- Update cgr.dev/chainguard/jre:latest docker digest to fba813a

### Fixed

- Update dependency org.bouncycastle:bcprov-jdk18on to v1.80
- Correct typo


## [0.0.2] - 2025-01-15

### Added

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

### Changed

- Improve workflows and friends
- Update cgr.dev/chainguard/jre:latest docker digest to fba813a
- Update plugin org.openapi.generator to v7.10.0
- Refactor, clean up, fix deprecated warnings
- Expose public jwk on endpoint and include kid in jwk
- Change configured host in dev profile to https://local.dev.swedenconnect.se:8443

### Fixed

- Correct release vars
- Make test run with bogus cert
- Update spring non-major
- Fix linting issues

## [0.0.1] - 2024-11-22

### Added

- Add ci,image,renovate,etc

### Changed

- Chore: cleanup and add workflow.
- Initial commit

### Fixed

- Update zxing to v3.5.3
- Update spring non-major

[0.0.18]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.17..v0.0.18
[0.0.17]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.15..v0.0.17
[0.0.15]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/0.0.15-diggdev..v0.0.15
[0.0.15-diggdev]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.14..0.0.15-diggdev
[0.0.14]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.13..v0.0.14
[0.0.13]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.12..v0.0.13
[0.0.12]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.11..v0.0.12
[0.0.11]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.10..v0.0.11
[0.0.10]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.9..v0.0.10
[0.0.9]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.8..v0.0.9
[0.0.8]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.7..v0.0.8
[0.0.7]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.6..v0.0.7
[0.0.6]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.5..v0.0.6
[0.0.5]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.4..v0.0.5
[0.0.4]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.3..v0.0.4
[0.0.3]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.2..v0.0.3
[0.0.2]: https://github.com/diggsweden/eudiw-wallet-issuer-poc/compare/v0.0.1..v0.0.2

<!-- generated by git-cliff -->
