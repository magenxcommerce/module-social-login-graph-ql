# Changelog

## [2.0.3](https://github.com/magenxcommerce/module-social-login-graph-ql/compare/v2.0.2...v2.0.3) (2026-09-18)


### Bug Fixes

* Reverting the env change and adding the admin config instead ([#16](https://github.com/magenxcommerce/module-social-login-graph-ql/issues/16)) ([7e6bf71](https://github.com/magenxcommerce/module-social-login-graph-ql/commit/7e6bf71de07eb82db827c4c518f46b6b10d2acc9))

## [2.0.2](https://github.com/magenxcommerce/module-social-login-graph-ql/compare/v2.0.1...v2.0.2) (2026-09-17)


### Bug Fixes

* read env from $_ENV and $_SERVER, not getenv() alone ([b57cf24](https://github.com/magenxcommerce/module-social-login-graph-ql/commit/b57cf24519c8f92389c45c8103c1d36bc03fadd7))
* Support environment variables from multiple sources ([#14](https://github.com/magenxcommerce/module-social-login-graph-ql/issues/14)) ([b57cf24](https://github.com/magenxcommerce/module-social-login-graph-ql/commit/b57cf24519c8f92389c45c8103c1d36bc03fadd7))

## [2.0.1](https://github.com/magenxcommerce/module-social-login-graph-ql/compare/v2.0.0...v2.0.1) (2026-09-17)


### Bug Fixes

* Change firebase/php-jwt version to ^7.1 ([#12](https://github.com/magenxcommerce/module-social-login-graph-ql/issues/12)) ([99ec9c0](https://github.com/magenxcommerce/module-social-login-graph-ql/commit/99ec9c0bc7a0ede9e17bc2406469ac9de32c02b9))

## [2.0.0](https://github.com/magenxcommerce/module-social-login-graph-ql/compare/v1.0.2...v2.0.0) (2026-09-17)


### ⚠ BREAKING CHANGES

* SocialLoginInput takes `idToken` instead of `email`. Callers must pass the provider's ID token; `firstname`/`lastname` remain only as a display-name fallback for tokens without name claims (Apple), and never influence which account is matched. Each issuer needs a client id configured (`*_client_id` / `MAGENX_SOCIAL_LOGIN_*_CLIENT_ID`) or its tokens are rejected.

### Bug Fixes

* Add ID token verification to social login mutation ([#10](https://github.com/magenxcommerce/module-social-login-graph-ql/issues/10)) ([8302803](https://github.com/magenxcommerce/module-social-login-graph-ql/commit/830280301ced742e84f008f284c67190e630f2fe))

## [1.0.2](https://github.com/magenxcommerce/module-social-login-graph-ql/compare/v1.0.1...v1.0.2) (2026-09-11)


### Bug Fixes

* Improve Store header validation error messaging in GraphQL ([#8](https://github.com/magenxcommerce/module-social-login-graph-ql/issues/8)) ([168f583](https://github.com/magenxcommerce/module-social-login-graph-ql/commit/168f583cca5abe3c7031ce4ef549eb73381d6996))
* report an unresolvable store as a clear input error ([168f583](https://github.com/magenxcommerce/module-social-login-graph-ql/commit/168f583cca5abe3c7031ce4ef549eb73381d6996))

## [1.0.1](https://github.com/magenxcommerce/module-social-login-graph-ql/compare/v1.0.0...v1.0.1) (2026-08-12)


### Bug Fixes

* Add security checks and improve social login resolver ([#4](https://github.com/magenxcommerce/module-social-login-graph-ql/issues/4)) ([836b821](https://github.com/magenxcommerce/module-social-login-graph-ql/commit/836b8219e3f68105e64e7044d56e07d571c9d650))
* harden socialLogin resolver and drop unused dependency ([836b821](https://github.com/magenxcommerce/module-social-login-graph-ql/commit/836b8219e3f68105e64e7044d56e07d571c9d650))

## 1.0.0 (2026-08-11)


### Miscellaneous Chores

* MagenX Commerce Magento 2 module ([32b599e](https://github.com/magenxcommerce/module-social-login-graph-ql/commit/32b599ea43307ff7e1dc689b303f50b8cc7a5065))
* Magenxcommerce composer namespace ([1e171ab](https://github.com/magenxcommerce/module-social-login-graph-ql/commit/1e171ab14b1ce7b1846765c2e30a5848637c35f6))
