//! What an approved brokered `use` op lets the daemon serve again WITHOUT a new
//! approval — the signed `scope.reuse` (design/approvals-inbox.md D1).
//!
//! ONE classifier, three consumers: the proxy stamps it into the op scope at
//! mint (so the approver reads it), approve asserts the signed fields equal
//! what this classifier returns for the record's PolicyContext, and the Use
//! apply picks its grant from it. The three can't drift because none of them
//! re-derives the mapping.
//!
//! Authorization is separate from value supply. An approval leaves a permit
//! that carries no value (`state::PermitKey`): keyed by what it reuses (the
//! request line and tier, or the policy unit that produced the ask) and by
//! the credentials the request resolved. A later request is served without
//! asking only when its own decision, re-run on that request, yields the
//! same key with a live permit (`state::AppState::authorize`). Whether a
//! value happens to be resident in memory never authorizes anything.
//!
//! The values (all bound to the approving agent, the connection, and the
//! destination host; the device is implicit, the ledger lives in this daemon):
//!
//! - `none`: nothing reusable. `ask-always` (and an `ask` from a rule with no
//!   id, which has no unit to key, scoped path or not) mints a single-use
//!   permit for exactly the approved request; its replay spends it. No
//!   `window_s` is stamped. (An `allow`-level request mints no op.)
//! - `exact`: a scoped ask (the service declares a `[requests]` shape for the
//!   path): only this identical request, with the same bound values, decided
//!   by the same unit, is reused within `window_s`.
//! - `rule`: a rule-matched ask: later requests of the same class (read or
//!   write, by the request's signed `method`) whose policy decision is the
//!   same rule (`reuse_rule`, its id; `reuse_label` when the rule has one)
//!   don't ask within `window_s`. A read approved under a rule never serves a
//!   write under it. Another rule, a floor ask, and ask-always requests still
//!   ask.
//! - `floor`: an ask from a default floor (no rule matched): later floor asks
//!   of the same class (`reuse_class`: `read` or `write`, by the method split
//!   the floors use) don't ask within `window_s`. A read approval never serves
//!   a write, and no rule-matched request rides it.
//!
//! A request-bound permit (`none` from an ask, `exact`) is redeemable only by
//! a request of the tier that minted it ([`BoundTier`]): an ask-always permit
//! only by an ask-always request, an `exact` permit only by a scoped ask of
//! the same unit, a single-use ask permit only by an ask a rule with no id
//! decided. Every permit serves only a request with the same credentials:
//! another or an extra role, or a connection rebound to other KEYs, asks
//! again.
//!
//! Every window is an upper bound: any policy change (and a lock) ends the
//! vault's windows; other vault changes keep them. A window can end early;
//! it never extends.

use crate::core::policy::{AccessLevel, DecidedBy};

/// Read vs write, by the same method split the default floors use (only
/// `GET`, `HEAD` and `OPTIONS` are reads; every other method is a write).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    Read,
    Write,
}

impl Class {
    pub fn of(method: &str) -> Class {
        if crate::core::policy::is_write_method(method) {
            Class::Write
        } else {
            Class::Read
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Class::Read => "read",
            Class::Write => "write",
        }
    }
}

/// The policy unit an ask approval belongs to: what decided it, and the
/// request's class. Keys a `rule` / `floor` window permit and a scoped ask's
/// `exact` permit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GrantUnit {
    /// A rule, by id, and the class of the request it decided: a read
    /// approved under a rule never serves a write under the same rule.
    Rule(String, Class),
    /// A default floor, by class.
    Floor(Class),
}

impl GrantUnit {
    /// The unit an `ask` decision belongs to. `None` for a rule with no id
    /// (nothing stable to key it by).
    pub fn of(decided_by: &DecidedBy, method: &str) -> Option<GrantUnit> {
        match decided_by {
            DecidedBy::Rule { id: Some(id), .. } => {
                Some(GrantUnit::Rule(id.clone(), Class::of(method)))
            }
            DecidedBy::Rule { id: None, .. } => None,
            DecidedBy::Floor => Some(GrantUnit::Floor(Class::of(method))),
        }
    }
}

/// How a request's `[requests]` shapes read it, which decides how an `ask`
/// approval of it is reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scoped {
    /// No shape matched: an `ask` is reused by its unit (rule or floor).
    No,
    /// A shape matched: an `ask` is reused only for the same covered values
    /// (`exact`).
    Yes,
    /// Single-use whatever decided it: a shape's method and path matched but
    /// its condition errored (a window would be the whole rule's, which is
    /// looser), or tied path readings decided by different units.
    Once,
}

impl From<bool> for Scoped {
    fn from(scoped: bool) -> Scoped {
        if scoped {
            Scoped::Yes
        } else {
            Scoped::No
        }
    }
}

impl Scoped {
    /// Stamp the signed marker into an op scope: `scoped` for a shape that
    /// matched, `single_use` for a forced single-use approval.
    pub fn stamp(self, scope: &mut serde_json::Value) {
        match self {
            Scoped::No => {}
            Scoped::Yes => scope["scoped"] = serde_json::Value::Bool(true),
            Scoped::Once => scope["single_use"] = serde_json::Value::Bool(true),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reuse {
    None,
    Exact,
    /// `class` is the request's class (from its signed `method`); it keys the
    /// ledger and is not a separate signed field.
    Rule {
        id: String,
        label: Option<String>,
        class: Class,
    },
    Floor(Class),
}

impl Reuse {
    /// The reuse an approval of a Use op minted under `level` grants.
    /// `decided_by` = what decided it; `scoped` = how `[requests]` shapes
    /// read the request (the signed `scoped` / `single_use` markers,
    /// [`Scoped`]); `method` = the request's method. `None` for `allow` and
    /// `deny`, which never mint an op.
    pub fn of(
        level: AccessLevel,
        decided_by: &DecidedBy,
        scoped: impl Into<Scoped>,
        method: &str,
    ) -> Option<Reuse> {
        let scoped = scoped.into();
        match level {
            AccessLevel::Deny | AccessLevel::Allow => None,
            AccessLevel::AskAlways => Some(Reuse::None),
            AccessLevel::Ask => Some(match GrantUnit::of(decided_by, method) {
                // A rule with no id has no unit: single-use, scoped or not.
                None => Reuse::None,
                Some(_) if scoped == Scoped::Once => Reuse::None,
                Some(_) if scoped == Scoped::Yes => Reuse::Exact,
                Some(GrantUnit::Rule(id, class)) => Reuse::Rule {
                    id,
                    label: match decided_by {
                        DecidedBy::Rule { label, .. } => label.clone(),
                        DecidedBy::Floor => None,
                    },
                    class,
                },
                Some(GrantUnit::Floor(class)) => Reuse::Floor(class),
            }),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Reuse::None => "none",
            Reuse::Exact => "exact",
            Reuse::Rule { .. } => "rule",
            Reuse::Floor(_) => "floor",
        }
    }

    /// The ledger unit this reuse writes (`rule` / `floor` only).
    pub fn unit(&self) -> Option<GrantUnit> {
        match self {
            Reuse::Rule { id, class, .. } => Some(GrantUnit::Rule(id.clone(), *class)),
            Reuse::Floor(c) => Some(GrantUnit::Floor(*c)),
            Reuse::None | Reuse::Exact => None,
        }
    }

    /// The signed `window_s` that accompanies this reuse: the policy ttl,
    /// except `none`, which has no window.
    pub fn window(&self, ttl_seconds: u64) -> Option<u64> {
        match self {
            Reuse::None => None,
            Reuse::Exact | Reuse::Rule { .. } | Reuse::Floor(_) => Some(ttl_seconds),
        }
    }

    /// The signed fields, in the order the scope carries them: `reuse`, then
    /// `reuse_rule` + optional `reuse_label` (rule) or `reuse_class` (floor).
    fn fields(&self) -> Vec<(&'static str, String)> {
        let mut out = vec![("reuse", self.as_str().to_string())];
        match self {
            Reuse::Rule { id, label, .. } => {
                out.push(("reuse_rule", id.clone()));
                if let Some(l) = label {
                    out.push(("reuse_label", l.clone()));
                }
            }
            Reuse::Floor(c) => out.push(("reuse_class", c.as_str().to_string())),
            Reuse::None | Reuse::Exact => {}
        }
        out
    }

    /// Stamp this reuse into an op scope: its fields plus `window_s` (integer
    /// seconds; JCS rejects floats) exactly when it has a window.
    pub fn stamp(&self, scope: &mut serde_json::Value, ttl_seconds: u64) {
        for (k, v) in self.fields() {
            scope[k] = serde_json::Value::String(v);
        }
        if let Some(w) = self.window(ttl_seconds) {
            scope["window_s"] = serde_json::Value::from(w);
        }
    }

    /// Apply-time: the signed reuse fields and `window_s` must be exactly the
    /// ones [`Self::stamp`] writes for this reuse. `Err` names the field.
    pub fn check_signed(&self, scope: &serde_json::Value, ttl_seconds: u64) -> Result<(), String> {
        let reuse = scope
            .get("reuse")
            .ok_or("signed level without signed reuse")?
            .as_str()
            .ok_or("signed reuse is not a string")?;
        if reuse != self.as_str() {
            return Err(format!(
                "signed reuse '{}' does not match what this approval grants ('{}')",
                reuse,
                self.as_str()
            ));
        }
        let want = self.fields();
        for k in ["reuse_rule", "reuse_label", "reuse_class"] {
            let signed = scope.get(k);
            let expected = want.iter().find(|(f, _)| *f == k).map(|(_, v)| v);
            let ok = match (signed, expected) {
                (None, None) => true,
                (Some(s), Some(e)) => s.as_str() == Some(e.as_str()),
                _ => false,
            };
            if !ok {
                return Err(format!(
                    "signed {} does not match what this approval grants",
                    k
                ));
            }
        }
        match (self.window(ttl_seconds), scope.get("window_s")) {
            (None, None) => Ok(()),
            (None, Some(_)) => Err(format!(
                "signed window_s on a '{}' approval, which has no window",
                self.as_str()
            )),
            (Some(want), None) => Err(format!(
                "signed window_s missing (this approval holds for {}s)",
                want
            )),
            (Some(want), Some(w)) => {
                let w = w.as_u64().ok_or("signed window_s is not an integer")?;
                if w == want {
                    Ok(())
                } else {
                    Err(format!(
                        "signed window_s {} does not match the policy window ({}s)",
                        w, want
                    ))
                }
            }
        }
    }
}

/// The tier a request-bound permit was minted under, stored as part of its
/// key: a permit is redeemable only by a request whose own decision yields
/// the same tier, so no tier spends or reuses another's approval for the
/// same request line.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BoundTier {
    /// Minted by an `ask-always` approval. Single-use; redeemed only by an
    /// `ask-always` request.
    AskAlways,
    /// Minted by an `ask` a rule with no id decided (reuse `none`).
    /// Single-use; redeemed only by an `ask` a rule with no id decided.
    AskOnce,
    /// Minted by a scoped `ask` (reuse `exact`) under this unit. Reused within
    /// its window; redeemed only by a scoped `ask` the same unit decided.
    Exact(GrantUnit),
}

impl BoundTier {
    /// The tier for a decision: what an approval of it mints, and the only
    /// tier a request with that decision may redeem. `None` when the decision
    /// has no request-bound permit (`allow`, `deny`, and an unscoped `ask`
    /// with a unit, which a unit permit serves). Mint and redeem both call
    /// this, so they cannot disagree.
    pub fn of(
        level: AccessLevel,
        decided_by: &DecidedBy,
        scoped: impl Into<Scoped>,
        method: &str,
    ) -> Option<BoundTier> {
        match (level, Reuse::of(level, decided_by, scoped.into(), method)?) {
            (AccessLevel::AskAlways, _) => Some(BoundTier::AskAlways),
            (AccessLevel::Ask, Reuse::None) => Some(BoundTier::AskOnce),
            (AccessLevel::Ask, Reuse::Exact) => {
                GrantUnit::of(decided_by, method).map(BoundTier::Exact)
            }
            _ => None,
        }
    }

    /// Whether redeeming spends the permit (single-use tiers) or only reads
    /// it (`exact`, reused within its window).
    pub fn single_use(&self) -> bool {
        !matches!(self, BoundTier::Exact(_))
    }
}

/// The signed scoping markers of a Use op ([`Scoped::stamp`]).
pub fn scoped(scope: &serde_json::Value) -> Scoped {
    let marked = |k: &str| scope.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
    if marked("single_use") {
        Scoped::Once
    } else if marked("scoped") {
        Scoped::Yes
    } else {
        Scoped::No
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(id: Option<&str>, label: Option<&str>) -> DecidedBy {
        DecidedBy::Rule {
            id: id.map(str::to_string),
            label: label.map(str::to_string),
            label_zh: None,
            consent: None,
        }
    }

    #[test]
    fn classification_table() {
        use AccessLevel::*;
        let send = rule(Some("send"), Some("Send email"));
        assert_eq!(
            Reuse::of(AskAlways, &send, false, "POST"),
            Some(Reuse::None)
        );
        assert_eq!(Reuse::of(AskAlways, &send, true, "POST"), Some(Reuse::None));
        assert_eq!(Reuse::of(Ask, &send, true, "POST"), Some(Reuse::Exact));
        assert_eq!(
            Reuse::of(Ask, &DecidedBy::Floor, true, "GET"),
            Some(Reuse::Exact)
        );
        assert_eq!(
            Reuse::of(Ask, &send, false, "POST"),
            Some(Reuse::Rule {
                id: "send".into(),
                label: Some("Send email".into()),
                class: Class::Write,
            })
        );
        // The rule unit carries the request's class.
        assert_eq!(
            Reuse::of(Ask, &send, false, "GET").and_then(|r| r.unit()),
            Some(GrantUnit::Rule("send".into(), Class::Read))
        );
        assert_eq!(
            Reuse::of(Ask, &send, false, "delete").and_then(|r| r.unit()),
            Some(GrantUnit::Rule("send".into(), Class::Write))
        );
        assert_eq!(
            Reuse::of(Ask, &DecidedBy::Floor, false, "GET"),
            Some(Reuse::Floor(Class::Read))
        );
        assert_eq!(
            Reuse::of(Ask, &DecidedBy::Floor, false, "DELETE"),
            Some(Reuse::Floor(Class::Write))
        );
        // A rule with no id has no unit: single-use, on a scoped path too.
        assert_eq!(
            Reuse::of(Ask, &rule(None, Some("x")), false, "GET"),
            Some(Reuse::None)
        );
        assert_eq!(
            Reuse::of(Ask, &rule(None, Some("x")), true, "POST"),
            Some(Reuse::None)
        );
        // An allow-level request mints no op.
        assert_eq!(Reuse::of(Allow, &DecidedBy::Floor, false, "GET"), None);
        assert_eq!(Reuse::of(Deny, &send, false, "GET"), None);
        assert_eq!(Reuse::None.window(900), None);
        assert_eq!(Reuse::Exact.window(60), Some(60));
        assert_eq!(Reuse::Floor(Class::Read).window(300), Some(300));
    }

    #[test]
    fn stamp_and_check_round_trip_and_refuse_any_difference() {
        let cases = [
            Reuse::None,
            Reuse::Exact,
            Reuse::Rule {
                id: "send".into(),
                label: Some("Send email".into()),
                class: Class::Write,
            },
            Reuse::Rule {
                id: "send".into(),
                label: None,
                class: Class::Read,
            },
            Reuse::Floor(Class::Write),
        ];
        for r in &cases {
            let mut s = json!({ "level": "ask" });
            r.stamp(&mut s, 900);
            assert!(r.check_signed(&s, 900).is_ok(), "{r:?} {s}");
            assert!(r.check_signed(&s, 60).is_err() || r.window(900).is_none());
        }
        let floor_read = Reuse::Floor(Class::Read);
        let mut s = json!({});
        floor_read.stamp(&mut s, 300);
        assert_eq!(
            s,
            json!({ "reuse": "floor", "reuse_class": "read", "window_s": 300 })
        );
        assert!(Reuse::Floor(Class::Write).check_signed(&s, 300).is_err());
        let rule_a = Reuse::Rule {
            id: "a".into(),
            label: None,
            class: Class::Read,
        };
        let mut s = json!({});
        rule_a.stamp(&mut s, 60);
        // The class is not a separate signed field of a rule reuse.
        assert!(s.get("reuse_class").is_none());
        let rule_b = Reuse::Rule {
            id: "b".into(),
            label: None,
            class: Class::Read,
        };
        assert!(rule_b.check_signed(&s, 60).is_err());
        // An extra field the reuse does not carry is refused too.
        s["reuse_class"] = json!("read");
        assert!(rule_a.check_signed(&s, 60).is_err());
        assert!(Reuse::Exact
            .check_signed(&json!({ "reuse": "exact" }), 60)
            .is_err());
    }

    /// Mint and redeem derive the request-bound tier from the same decision:
    /// each tier is distinct, so none redeems another's grant.
    #[test]
    fn bound_tier_per_decision() {
        use AccessLevel::*;
        let send = rule(Some("send"), None);
        let anon = rule(None, None);
        assert_eq!(
            BoundTier::of(AskAlways, &send, false, "POST"),
            Some(BoundTier::AskAlways)
        );
        assert_eq!(
            BoundTier::of(AskAlways, &DecidedBy::Floor, true, "POST"),
            Some(BoundTier::AskAlways)
        );
        assert_eq!(
            BoundTier::of(Ask, &send, true, "POST"),
            Some(BoundTier::Exact(GrantUnit::Rule(
                "send".into(),
                Class::Write
            )))
        );
        assert_eq!(
            BoundTier::of(Ask, &DecidedBy::Floor, true, "GET"),
            Some(BoundTier::Exact(GrantUnit::Floor(Class::Read)))
        );
        assert_eq!(
            BoundTier::of(Ask, &anon, false, "POST"),
            Some(BoundTier::AskOnce)
        );
        assert_eq!(
            BoundTier::of(Ask, &anon, true, "POST"),
            Some(BoundTier::AskOnce)
        );
        // Ledger-served and non-ask decisions have no request-bound tier.
        assert_eq!(BoundTier::of(Ask, &send, false, "POST"), None);
        assert_eq!(BoundTier::of(Ask, &DecidedBy::Floor, false, "GET"), None);
        assert_eq!(BoundTier::of(Allow, &send, false, "GET"), None);
        assert_eq!(BoundTier::of(Deny, &send, false, "GET"), None);
        assert!(BoundTier::AskAlways.single_use());
        assert!(BoundTier::AskOnce.single_use());
        assert!(!BoundTier::Exact(GrantUnit::Floor(Class::Read)).single_use());
        // The same rule on a read and a write are different units.
        assert_ne!(
            BoundTier::of(Ask, &send, true, "GET"),
            BoundTier::of(Ask, &send, true, "POST")
        );
    }

    /// A forced single-use approval is single-use whatever decided it, and
    /// its signed marker reads back.
    #[test]
    fn a_forced_single_use_is_single_use() {
        use AccessLevel::*;
        let send = rule(Some("send"), None);
        assert_eq!(Reuse::of(Ask, &send, Scoped::Once, "POST"), Some(Reuse::None));
        assert_eq!(Reuse::of(Ask, &DecidedBy::Floor, Scoped::Once, "GET"), Some(Reuse::None));
        assert_eq!(BoundTier::of(Ask, &send, Scoped::Once, "POST"), Some(BoundTier::AskOnce));
        for s in [Scoped::No, Scoped::Yes, Scoped::Once] {
            let mut scope = json!({});
            s.stamp(&mut scope);
            assert_eq!(scoped(&scope), s);
        }
    }
}
