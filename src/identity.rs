//! Caller identity for playbook executions is derived server-side.
//!
//! A playbook that reads or writes per-user data addresses it by an identity
//! variable (`uid`, `user_uid`). Those values must come from the verified
//! session, never from the request body: the gateway overwrites them with the
//! session's Auth0 subject before dispatch, and refuses to dispatch when the
//! request names an identity but the session has none to give.
//!
//! The binding is applied to the top-level execution variables only, which is
//! where the SPA and every playbook put them.

use serde_json::Value;

/// Execution variables that name the acting user.
pub const IDENTITY_VARS: &[&str] = &["uid", "user_uid"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// The request names an identity but the session carries no subject.
    NoSubject,
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityError::NoSubject => write!(
                f,
                "this session has no verified identity for a user-scoped playbook; sign in again"
            ),
        }
    }
}

/// What `bind_identity` did, for logging.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Binding {
    /// Identity variables present in the request and set to the subject.
    pub bound: Vec<&'static str>,
    /// Of those, the ones whose client-supplied value differed from the subject.
    pub overridden: Vec<&'static str>,
}

/// Overwrite every identity variable present in `args` with `subject`.
///
/// * Variables the request does not carry are left absent: a playbook that does
///   not ask for an identity is not handed one.
/// * A variable that is explicitly `null` claims no identity and is left `null`.
///   Callers use it to mean "anonymous" (e.g. the SPA's calendar read for a
///   conversation-scoped calendar), and a null cannot act as anyone. Binding it
///   would silently turn an anonymous request into a per-user one. Any other
///   value, including `""`, is a claim and is bound.
/// * A present variable with no `subject` fails closed. The exception is
///   `allow_unbound` (development auth bypass), where nothing is changed.
/// * Non-object `args` carry no identity and pass through.
pub fn bind_identity(args: &mut Value, subject: Option<&str>, allow_unbound: bool) -> Result<Binding, IdentityError> {
    let Value::Object(map) = args else {
        return Ok(Binding::default());
    };
    let present: Vec<&'static str> = IDENTITY_VARS
        .iter()
        .copied()
        .filter(|k| map.get(*k).is_some_and(|v| !v.is_null()))
        .collect();
    if present.is_empty() {
        return Ok(Binding::default());
    }
    let subject = match subject.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => s,
        None if allow_unbound => return Ok(Binding::default()),
        None => return Err(IdentityError::NoSubject),
    };
    let mut binding = Binding::default();
    for key in present {
        if map.get(key).and_then(Value::as_str) != Some(subject) {
            binding.overridden.push(key);
        }
        map.insert(key.to_string(), Value::String(subject.to_string()));
        binding.bound.push(key);
    }
    Ok(binding)
}

/// Like [`bind_identity`], but sets EVERY identity variable whether or not the
/// request carries it, `null` included. For reruns: the server replays the
/// SOURCE execution's stored workload, so an identity the request omits would
/// otherwise be the source's, not the caller's.
pub fn bind_identity_all(
    args: &mut Value,
    subject: Option<&str>,
    allow_unbound: bool,
) -> Result<Binding, IdentityError> {
    if !args.is_object() {
        *args = Value::Object(Default::default());
    }
    let subject = match subject.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => s,
        None if allow_unbound => return Ok(Binding::default()),
        None => return Err(IdentityError::NoSubject),
    };
    let mut binding = Binding::default();
    if let Value::Object(map) = args {
        for key in IDENTITY_VARS {
            if map.get(*key).and_then(Value::as_str) != Some(subject) {
                binding.overridden.push(key);
            }
            map.insert(key.to_string(), Value::String(subject.to_string()));
            binding.bound.push(key);
        }
    }
    Ok(binding)
}

/// Bind identity inside a request body the REST proxy forwards to NoETL.
///
/// Covers every route that starts an execution with caller-supplied variables:
/// `execute` (workload under `payload` or its alias `workload`),
/// `execute/batch` (`executions[]` of the same shape) and
/// `executions/{id}/rerun` (forced, see [`bind_identity_all`]).
/// Returns the rewritten body, or `None` when nothing needed changing.
pub fn bind_identity_in_body(
    path: &str,
    body: &[u8],
    subject: Option<&str>,
    allow_unbound: bool,
) -> Result<Option<Vec<u8>>, IdentityError> {
    let path = path.trim_matches('/');
    let segments: Vec<&str> = path.split('/').collect();
    let is_rerun = segments.len() == 3 && segments[0] == "executions" && segments[2] == "rerun";
    if !(path == "execute" || path == "execute/batch" || is_rerun) {
        return Ok(None);
    }
    let mut doc: Value = if body.is_empty() {
        Value::Object(Default::default())
    } else {
        match serde_json::from_slice(body) {
            Ok(v) => v,
            // Not JSON: the server will reject it, and it cannot carry an identity.
            Err(_) => return Ok(None),
        }
    };
    if !doc.is_object() {
        return Ok(None);
    }

    fn bind_workloads(item: &mut Value, subject: Option<&str>, allow: bool, force: bool) -> Result<(), IdentityError> {
        let Value::Object(map) = item else { return Ok(()) };
        let mut seen = false;
        for key in ["payload", "workload"] {
            if let Some(w) = map.get_mut(key) {
                seen = true;
                if force {
                    bind_identity_all(w, subject, allow)?;
                } else {
                    bind_identity(w, subject, allow)?;
                }
            }
        }
        if force && !seen {
            let mut w = Value::Object(Default::default());
            bind_identity_all(&mut w, subject, allow)?;
            map.insert("workload".to_string(), w);
        }
        Ok(())
    }

    if path == "execute/batch" {
        if let Some(Value::Array(items)) = doc.get_mut("executions") {
            for item in items.iter_mut() {
                bind_workloads(item, subject, allow_unbound, false)?;
            }
        }
    } else {
        bind_workloads(&mut doc, subject, allow_unbound, is_rerun)?;
    }
    let out = serde_json::to_vec(&doc).unwrap_or_else(|_| body.to_vec());
    Ok(if out == body { None } else { Some(out) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ME: &str = "auth0|caller";

    #[test]
    fn a_client_supplied_uid_is_replaced_by_the_session_subject() {
        let mut args = json!({"uid": "auth0|someone-else", "profile": {}, "read_only": true});
        let b = bind_identity(&mut args, Some(ME), false).unwrap();
        assert_eq!(args["uid"], ME);
        assert_eq!(b.overridden, vec!["uid"]);
        // Everything that is not an identity is untouched.
        assert_eq!(args["profile"], json!({}));
        assert_eq!(args["read_only"], true);
    }

    #[test]
    fn user_uid_is_bound_too() {
        let mut args = json!({"user_uid": "auth0|someone-else", "thread_id": "t1"});
        bind_identity(&mut args, Some(ME), false).unwrap();
        assert_eq!(args["user_uid"], ME);
        assert_eq!(args["thread_id"], "t1");
    }

    #[test]
    fn a_matching_uid_is_bound_without_counting_as_an_override() {
        let mut args = json!({"uid": ME});
        let b = bind_identity(&mut args, Some(ME), false).unwrap();
        assert_eq!(b.bound, vec!["uid"]);
        assert!(b.overridden.is_empty());
    }

    #[test]
    fn non_string_and_blank_identities_are_replaced() {
        for bad in [json!(""), json!(7), json!({"x": 1}), json!([ME])] {
            let mut args = json!({"uid": bad});
            bind_identity(&mut args, Some(ME), false).unwrap();
            assert_eq!(args["uid"], ME);
        }
    }

    /// An explicit `null` is "anonymous", not a claim: it stays null, so a
    /// conversation-scoped calendar read is not turned into a per-user one, and
    /// it needs no subject.
    #[test]
    fn an_explicit_null_identity_is_left_anonymous() {
        let mut args = json!({"user_uid": null, "thread_path": "chat_threads/t", "trip_id": "x"});
        let b = bind_identity(&mut args, Some(ME), false).unwrap();
        assert_eq!(args["user_uid"], Value::Null);
        assert!(b.bound.is_empty());
        let mut args = json!({"user_uid": null});
        assert!(bind_identity(&mut args, None, false).is_ok(), "no subject needed for an anonymous request");
        // A null next to a real claim: only the claim is bound.
        let mut args = json!({"uid": "auth0|someone-else", "user_uid": null});
        bind_identity(&mut args, Some(ME), false).unwrap();
        assert_eq!(args["uid"], ME);
        assert_eq!(args["user_uid"], Value::Null);
    }

    #[test]
    fn a_rerun_binds_even_a_null_identity() {
        let mut args = json!({"user_uid": null});
        bind_identity_all(&mut args, Some(ME), false).unwrap();
        assert_eq!(args["user_uid"], ME);
        assert_eq!(args["uid"], ME);
    }

    #[test]
    fn no_subject_fails_closed_when_an_identity_is_requested() {
        let mut args = json!({"uid": "auth0|someone-else"});
        assert_eq!(bind_identity(&mut args, None, false), Err(IdentityError::NoSubject));
        assert_eq!(
            bind_identity(&mut args, Some("  "), false),
            Err(IdentityError::NoSubject)
        );
        // Refused, not rewritten: nothing was dispatched with the client's value either.
        assert_eq!(args["uid"], "auth0|someone-else");
    }

    #[test]
    fn a_playbook_that_asks_for_no_identity_is_not_given_one() {
        let mut args = json!({"city": "Paris"});
        let b = bind_identity(&mut args, Some(ME), false).unwrap();
        assert!(b.bound.is_empty());
        assert!(args.get("uid").is_none());
        // ...and needs no subject at all.
        bind_identity(&mut args, None, false).unwrap();
    }

    #[test]
    fn dev_bypass_passes_unbound_requests_through_unchanged() {
        let mut args = json!({"uid": "dev-user"});
        bind_identity(&mut args, None, true).unwrap();
        assert_eq!(args["uid"], "dev-user");
        // A real subject still wins even in bypass.
        bind_identity(&mut args, Some(ME), true).unwrap();
        assert_eq!(args["uid"], ME);
    }

    #[test]
    fn rerun_binding_sets_identities_the_request_omitted() {
        let mut args = json!({"request_id": "r1"});
        bind_identity_all(&mut args, Some(ME), false).unwrap();
        assert_eq!(args["uid"], ME);
        assert_eq!(args["user_uid"], ME);
        assert_eq!(args["request_id"], "r1");
        assert_eq!(
            bind_identity_all(&mut json!({}), None, false),
            Err(IdentityError::NoSubject)
        );
    }

    fn body(v: Value) -> Vec<u8> {
        serde_json::to_vec(&v).unwrap()
    }

    fn rebound(path: &str, v: Value) -> Value {
        let out = bind_identity_in_body(path, &body(v.clone()), Some(ME), false).unwrap();
        out.map(|b| serde_json::from_slice(&b).unwrap()).unwrap_or(v)
    }

    #[test]
    fn proxy_execute_binds_payload_and_its_workload_alias() {
        let v = rebound("execute", json!({"path": "p", "payload": {"uid": "auth0|other"}}));
        assert_eq!(v["payload"]["uid"], ME);
        let v = rebound(
            "/execute/",
            json!({"path": "p", "workload": {"user_uid": "auth0|other"}}),
        );
        assert_eq!(v["workload"]["user_uid"], ME);
        assert_eq!(v["path"], "p");
    }

    #[test]
    fn proxy_batch_binds_every_item() {
        let v = rebound(
            "execute/batch",
            json!({"executions": [
                {"path": "a", "payload": {"uid": "auth0|x"}},
                {"path": "b", "workload": {"uid": "auth0|y"}},
                {"path": "c", "payload": {"city": "Paris"}}
            ]}),
        );
        assert_eq!(v["executions"][0]["payload"]["uid"], ME);
        assert_eq!(v["executions"][1]["workload"]["uid"], ME);
        assert!(v["executions"][2]["payload"].get("uid").is_none());
    }

    #[test]
    fn proxy_rerun_is_forced_even_with_no_body() {
        let out = bind_identity_in_body("executions/123/rerun", b"", Some(ME), false)
            .unwrap()
            .unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["workload"]["uid"], ME);
        assert_eq!(v["workload"]["user_uid"], ME);
    }

    #[test]
    fn proxy_without_subject_refuses_identity_bearing_executions() {
        let b = body(json!({"path": "p", "payload": {"uid": "auth0|other"}}));
        assert_eq!(
            bind_identity_in_body("execute", &b, None, false),
            Err(IdentityError::NoSubject)
        );
        assert_eq!(
            bind_identity_in_body("executions/9/rerun", b"", None, false),
            Err(IdentityError::NoSubject)
        );
    }

    #[test]
    fn proxy_leaves_other_routes_and_identity_free_bodies_alone() {
        let b = body(json!({"payload": {"uid": "auth0|other"}}));
        assert_eq!(bind_identity_in_body("catalog/list", &b, None, false), Ok(None));
        assert_eq!(bind_identity_in_body("executions/1/cancel", &b, None, false), Ok(None));
        let free = body(json!({"path": "p", "payload": {"city": "Paris"}}));
        assert_eq!(bind_identity_in_body("execute", &free, None, false), Ok(None));
        assert_eq!(bind_identity_in_body("execute", b"not json", None, false), Ok(None));
    }

    #[test]
    fn non_object_args_pass_through() {
        let mut args = json!(["uid"]);
        bind_identity(&mut args, None, false).unwrap();
        assert_eq!(args, json!(["uid"]));
    }
}
