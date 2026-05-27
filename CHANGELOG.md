# Changelog

All notable changes to this project will be documented in this file.

## [2.11.2](https://github.com/noetl/gateway/compare/v2.11.1...v2.11.2) (2026-05-27)

### Bug Fixes

* **playbook_state:** add per-message INFO log + panic surfacing ([#13](https://github.com/noetl/gateway/issues/13)) ([6f9267e](https://github.com/noetl/gateway/commit/6f9267e2c174dd9365092ae1ea3c7a8ff3c91aa8)), closes [#12](https://github.com/noetl/gateway/issues/12) [#120](https://github.com/noetl/gateway/issues/120) [#620](https://github.com/noetl/gateway/issues/620)

## [2.11.1](https://github.com/noetl/gateway/compare/v2.11.0...v2.11.1) (2026-05-27)

### Bug Fixes

* **playbook_state:** extract execution_id from noetl.events subject shape ([#12](https://github.com/noetl/gateway/issues/12)) ([5dc2339](https://github.com/noetl/gateway/commit/5dc2339009d8eca817d929cdac2e1a971ca7818f))

## [2.11.0](https://github.com/noetl/gateway/compare/v2.10.1...v2.11.0) (2026-05-24)

### Features

* **sse:** firestore subscriptions + playbook/state lifecycle frames ([#11](https://github.com/noetl/gateway/issues/11)) ([03b9684](https://github.com/noetl/gateway/commit/03b968405b6f66f55fe0264b3b958613e16003f4))

## [2.10.1](https://github.com/noetl/gateway/compare/v2.10.0...v2.10.1) (2026-05-14)

### Bug Fixes

* **auth:** fail fast and cancel timed-out auth playbooks ([8c777b8](https://github.com/noetl/gateway/commit/8c777b87fb4095d6e332aeb562b039b0bf01977d))

## [2.10.0](https://github.com/noetl/gateway/compare/v2.9.0...v2.10.0) (2026-04-27)

### Features

* align gateway with agent execution contract ([5b5aeb3](https://github.com/noetl/gateway/commit/5b5aeb3cf2b5ffc58e715e28b227cf0188aa2051))

### Bug Fixes

* tighten gateway agent execution contract ([635a4b0](https://github.com/noetl/gateway/commit/635a4b0bb98f829293b860f231ee8ec0d3387dc7))

## [2.9.0](https://github.com/noetl/gateway/compare/v2.8.8...v2.9.0) (2026-03-28)

### Features

* **gateway:** add runtime contract endpoint for cli/ai integration ([d5acf6d](https://github.com/noetl/gateway/commit/d5acf6de4cd0b7a2b1acd0488f38b6d8d2bc3777))

## [2.8.8](https://github.com/noetl/gateway/compare/v2.8.7...v2.8.8) (2026-03-17)

### Bug Fixes

* canonical execute payload and add rerun mutation ([a0af700](https://github.com/noetl/gateway/commit/a0af7000037b0f63b717e7ef088da29ccc384702))
* Update workflows AHM-4252 ([9789fc8](https://github.com/noetl/gateway/commit/9789fc80800197a3e1b39aa1cad3de611f8da5a5))

## 2.8.7 (2026-03-02)

### Bug Fixes

* make release input parsing event-safe ([535723b](https://github.com/noetl/gateway/commit/535723b52577bb36dee1b90401895d302c2ec6ea))
* release workflows on push and semantic auth ([c4a5565](https://github.com/noetl/gateway/commit/c4a5565be2ab8bb27631b22268c3bbc938aece46))
* remove secret expressions from workflow conditions ([e59aa01](https://github.com/noetl/gateway/commit/e59aa018ec71aa0cad8a84b3d73240a8e63180e9))
