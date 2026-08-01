# Changelog

All notable changes to this project will be documented in this file.

## [3.7.1](https://github.com/noetl/gateway/compare/v3.7.0...v3.7.1) (2026-08-01)

### Bug Fixes

* **startup:** require the EHDB feed + KV addresses instead of degrading silently ([508efaa](https://github.com/noetl/gateway/commit/508efaa2a0c4725d572eb32258720d5e4bdcd243))

## [3.7.0](https://github.com/noetl/gateway/compare/v3.6.0...v3.7.0) (2026-08-01)

### Features

* **callbacks:** drop the NATS callback listener ([151747d](https://github.com/noetl/gateway/commit/151747d3f08d67af6a2fb7889104b75af25e4291))

## [3.6.0](https://github.com/noetl/gateway/compare/v3.5.0...v3.6.0) (2026-08-01)

### Features

* **kv:** move the session cache and request store onto EHDB KV ([a1289a2](https://github.com/noetl/gateway/commit/a1289a2933e4d0b1403e7dec2c8b07cb8c1400a1)), closes [noetl/ehdb#307](https://github.com/noetl/ehdb/issues/307) [noetl/worker#202](https://github.com/noetl/worker/issues/202)

## [3.5.0](https://github.com/noetl/gateway/compare/v3.4.1...v3.5.0) (2026-07-31)

### Features

* **event-feed:** read execution lifecycle off the EHDB feed (flag-gated) ([2ef13d2](https://github.com/noetl/gateway/commit/2ef13d2fe6deeb7fd7bff55eabd10a7d3740a6b9))

## [3.4.1](https://github.com/noetl/gateway/compare/v3.4.0...v3.4.1) (2026-06-26)

### Bug Fixes

* **auth:** validate cache-missed sessions via auth0_validate_session playbook ([#31](https://github.com/noetl/gateway/issues/31)) ([c752eb2](https://github.com/noetl/gateway/commit/c752eb2751f5bc5b87a98e3256bb26544a276548))

## [3.4.0](https://github.com/noetl/gateway/compare/v3.3.0...v3.4.0) (2026-06-12)

### Features

* de-vendor the directive engine onto shared noetl-directives crate ([c29fafe](https://github.com/noetl/gateway/commit/c29fafe742c99598be233d3964f200cd81ba7f49)), closes [noetl/ai-meta#92](https://github.com/noetl/ai-meta/issues/92)

## [3.3.0](https://github.com/noetl/gateway/compare/v3.2.0...v3.3.0) (2026-06-12)

### Features

* push-ingress (Mode C) /ingress/{listener} + auth-gated directive trust ([#90](https://github.com/noetl/gateway/issues/90) Phase 3) ([#28](https://github.com/noetl/gateway/issues/28)) ([942022b](https://github.com/noetl/gateway/commit/942022b2952f4de329fa3a8f46249ea484c68b1a)), closes [noetl/gateway#27](https://github.com/noetl/gateway/issues/27)

## [3.2.0](https://github.com/noetl/gateway/compare/v3.1.0...v3.2.0) (2026-06-04)

### Features

* **sharding:** GET /sharding/preview diagnostic twin endpoint (Phase F R3b-2) ([#26](https://github.com/noetl/gateway/issues/26)) ([d3d4740](https://github.com/noetl/gateway/commit/d3d4740c46a9551f5ad2c401413e253c165184e1)), closes [noetl/ai-meta#49](https://github.com/noetl/ai-meta/issues/49) [noetl/gateway#25](https://github.com/noetl/gateway/issues/25) [noetl/ai-meta#49](https://github.com/noetl/ai-meta/issues/49) [noetl/server#47](https://github.com/noetl/server/issues/47)

## [3.1.0](https://github.com/noetl/gateway/compare/v3.0.0...v3.1.0) (2026-06-04)

### Features

* **sharding:** body-param JSON routing for events endpoints (Phase F R3a-2) ([#24](https://github.com/noetl/gateway/issues/24)) ([d92fd5e](https://github.com/noetl/gateway/commit/d92fd5edbd4a93105feba5a509f7011440b3f9ae)), closes [noetl/ai-meta#49](https://github.com/noetl/ai-meta/issues/49) [noetl/gateway#21](https://github.com/noetl/gateway/issues/21) [noetl/gateway#23](https://github.com/noetl/gateway/issues/23) [noetl/ai-meta#49](https://github.com/noetl/ai-meta/issues/49) [noetl/gateway#21](https://github.com/noetl/gateway/issues/21)

## [3.0.0](https://github.com/noetl/gateway/compare/v2.14.1...v3.0.0) (2026-06-04)

### ⚠ BREAKING CHANGES

* **sharding:** to wire shape or existing routes).

## Wiki update (Rule 2a)

noetl/gateway wiki `configuration` page gains a new "NoETL
shard map (Phase F R3a)" subsection covering the routes
covered + not covered by R3a, the TOML config shape, the
constraints enforced at startup, and the wire-contract
guarantee with the server-side shard_for().  Ships in
lockstep per `wiki-maintenance.md` Rule 2a.

### Features

* **sharding:** gateway-side shard routing infrastructure (Phase F R3a) ([#21](https://github.com/noetl/gateway/issues/21)) ([5f6892e](https://github.com/noetl/gateway/commit/5f6892ee41dd9da7293b1d71954008c624f1038a)), closes [noetl/ai-meta#49](https://github.com/noetl/ai-meta/issues/49) [noetl/server#45](https://github.com/noetl/server/issues/45) [noetl/ai-meta#49](https://github.com/noetl/ai-meta/issues/49) [noetl/gateway#20](https://github.com/noetl/gateway/issues/20) [noetl/ai-meta#49](https://github.com/noetl/ai-meta/issues/49) [noetl/server#45](https://github.com/noetl/server/issues/45)

## [2.14.1](https://github.com/noetl/gateway/compare/v2.14.0...v2.14.1) (2026-05-29)

### Bug Fixes

* **docker:** remove firestore-sidecar venv + orphan config refs after [#18](https://github.com/noetl/gateway/issues/18) ([#19](https://github.com/noetl/gateway/issues/19)) ([ca671ff](https://github.com/noetl/gateway/commit/ca671ff725b55f653f4227fe705fd318286d5b0f)), closes [noetl/ai-meta#26](https://github.com/noetl/ai-meta/issues/26) [noetl/ai-meta#23](https://github.com/noetl/ai-meta/issues/23)

## [2.14.0](https://github.com/noetl/gateway/compare/v2.13.0...v2.14.0) (2026-05-29)

### Features

* **gateway:** remove direct Firestore subscription subsystem ([#18](https://github.com/noetl/gateway/issues/18)) ([d1b5979](https://github.com/noetl/gateway/commit/d1b59798ce6c329c5124e36ac4d45eecfbce518b)), closes [noetl/ai-meta#23](https://github.com/noetl/ai-meta/issues/23) [noetl/ai-meta#25](https://github.com/noetl/ai-meta/issues/25) [noetl/ai-meta#23](https://github.com/noetl/ai-meta/issues/23) [noetl/ai-meta#23](https://github.com/noetl/ai-meta/issues/23) [noetl/ai-meta#23](https://github.com/noetl/ai-meta/issues/23)

## [2.13.0](https://github.com/noetl/gateway/compare/v2.12.0...v2.13.0) (2026-05-29)

### Features

* **sse:** forward calendar.event.touched on the gateway event channel ([#17](https://github.com/noetl/gateway/issues/17)) ([a8f863e](https://github.com/noetl/gateway/commit/a8f863eb4e26a12c3e39753cd9fc1582f6a81a69)), closes [noetl/ai-meta#23](https://github.com/noetl/ai-meta/issues/23) [noetl/ai-meta#25](https://github.com/noetl/ai-meta/issues/25) [noetl/ai-meta#23](https://github.com/noetl/ai-meta/issues/23)

## [2.12.0](https://github.com/noetl/gateway/compare/v2.11.4...v2.12.0) (2026-05-28)

### Features

* **gateway:** expose Auth0 metadata in runtime contract ([#16](https://github.com/noetl/gateway/issues/16)) ([b988b9f](https://github.com/noetl/gateway/commit/b988b9f39bcc0d4e5ad22fd6b88ec9633d31ed62)), closes [#124](https://github.com/noetl/gateway/issues/124) [#124](https://github.com/noetl/gateway/issues/124)

## [2.11.4](https://github.com/noetl/gateway/compare/v2.11.3...v2.11.4) (2026-05-27)

### Bug Fixes

* **sse:** log INFO when synthetic playbook/state send finds client absent ([#15](https://github.com/noetl/gateway/issues/15)) ([aaf6afb](https://github.com/noetl/gateway/commit/aaf6afbf5015097fabb6204f00669fc9dc3631ed))

## [2.11.3](https://github.com/noetl/gateway/compare/v2.11.2...v2.11.3) (2026-05-27)

### Bug Fixes

* **sse:** emit synthetic playbook/state from callback handler ([#14](https://github.com/noetl/gateway/issues/14)) ([3413b8d](https://github.com/noetl/gateway/commit/3413b8d0cdf4a8ce59c77191075b0b42aa667720))

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
