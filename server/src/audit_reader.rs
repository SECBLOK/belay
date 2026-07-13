use chrono::{DateTime, Timelike};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn bucket_key(ts: &str) -> Option<String> {
    let norm = ts.replace('Z', "+00:00");
    let dt = DateTime::parse_from_rfc3339(&norm).ok()?;
    // Use the offset-local (wall-clock) time — matches Python's dt.replace(minute=...) on dt itself
    let m = (dt.time().minute() / 5) * 5; // floor to 5-min
    Some(format!("{:02}:{:02}", dt.time().hour(), m))
}

#[derive(Serialize)]
pub struct PostureSummary {
    pub total: usize,
    pub allow: usize,
    pub ask: usize,
    pub deny: usize,
    pub score: i64,
    pub by_category: BTreeMap<String, usize>,
    pub trend: Vec<Value>,
    pub top_rules: Vec<Value>,
}

pub fn summarize(rows: &[Value]) -> PostureSummary {
    let verdict = |r: &Value| r["verdict"].as_str().unwrap_or("").to_string();
    let allow = rows.iter().filter(|r| verdict(r) == "allow").count();
    let ask = rows.iter().filter(|r| verdict(r) == "ask").count();
    let deny = rows.iter().filter(|r| verdict(r) == "deny").count();

    let mut by_cat: BTreeMap<String, usize> = BTreeMap::new();
    for r in rows {
        for rid in r["rules"].as_array().cloned().unwrap_or_default() {
            if let Some(rid) = rid.as_str() {
                *by_cat
                    .entry(rid.split('.').next().unwrap_or("").into())
                    .or_default() += 1;
            }
        }
    }
    let score = (100 - deny as i64 * 15 - ask as i64 * 5).clamp(0, 100);

    let mut buckets: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    for r in rows {
        let v = verdict(r);
        if !["allow", "ask", "deny"].contains(&v.as_str()) {
            continue;
        }
        if let Some(k) = bucket_key(r["ts"].as_str().unwrap_or("")) {
            let e = buckets.entry(k).or_default();
            match v.as_str() {
                "allow" => e.0 += 1,
                "ask" => e.1 += 1,
                _ => e.2 += 1,
            }
        }
    }
    let trend = buckets
        .iter()
        .map(|(k, (a, s, d))| json!({"bucket": k, "allow": a, "ask": s, "deny": d}))
        .collect();

    // Use IndexMap to preserve insertion (first-encounter) order — matches Python Counter.most_common
    let mut counts: indexmap::IndexMap<String, usize> = indexmap::IndexMap::new();
    for r in rows {
        if ["deny", "ask"].contains(&verdict(r).as_str()) {
            for rid in r["rules"].as_array().cloned().unwrap_or_default() {
                if let Some(rid) = rid.as_str() {
                    *counts.entry(rid.into()).or_default() += 1;
                }
            }
        }
    }
    // Stable sort: count desc, ties broken by insertion order (first-encountered wins)
    let mut ranked: Vec<_> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1)); // stable sort preserves insertion order on ties
    let top_rules = ranked
        .into_iter()
        .take(8)
        .map(|(rid, c)| {
            json!({"rule_id": rid, "count": c,
               "category": rid.split('.').next().unwrap_or("").to_string()})
        })
        .collect();

    PostureSummary {
        total: rows.len(),
        allow,
        ask,
        deny,
        score,
        by_category: by_cat,
        trend,
        top_rules,
    }
}

/// Port of `to_findings` from audit_reader.py.
/// Returns rows in REVERSED order, keeping only AuditRow fields that are present and non-null.
/// AuditRow fields: ts, event, session, tool, verdict, reason, rules
pub fn to_findings(rows: &[Value]) -> Value {
    const FIELDS: &[&str] = &[
        "ts", "event", "session", "tool", "verdict", "reason", "rules",
    ];
    let findings: Vec<Value> = rows
        .iter()
        .rev()
        .map(|r| {
            let mut obj = serde_json::Map::new();
            for &field in FIELDS {
                if let Some(v) = r.get(field) {
                    if !v.is_null() {
                        obj.insert(field.to_string(), v.clone());
                    }
                }
            }
            // Ensure default values match AuditRow pydantic defaults for missing fields
            // AuditRow defaults: ts="", event="", session="", tool="", verdict="", reason="", rules=[]
            for &field in FIELDS {
                if !obj.contains_key(field) {
                    if field == "rules" {
                        obj.insert(field.to_string(), json!([]));
                    } else {
                        obj.insert(field.to_string(), json!(""));
                    }
                }
            }
            Value::Object(obj)
        })
        .collect();
    json!(findings)
}

/// Port of `sessions` from audit_reader.py.
/// Groups rows by session, tracking events count, last_verdict, and last ts.
pub fn sessions(rows: &[Value]) -> Value {
    let mut out: indexmap::IndexMap<String, serde_json::Map<String, Value>> =
        indexmap::IndexMap::new();
    for r in rows {
        let s = r["session"].as_str().unwrap_or("?").to_string();
        let entry = out.entry(s.clone()).or_insert_with(|| {
            let mut m = serde_json::Map::new();
            m.insert("session".into(), json!(s));
            m.insert("events".into(), json!(0));
            m.insert("last_verdict".into(), json!(""));
            m.insert("ts".into(), json!(""));
            m
        });
        let events = entry["events"].as_i64().unwrap_or(0) + 1;
        entry.insert("events".into(), json!(events));
        entry.insert(
            "last_verdict".into(),
            json!(r["verdict"].as_str().unwrap_or("")),
        );
        entry.insert("ts".into(), json!(r["ts"].as_str().unwrap_or("")));
    }
    json!(out.values().collect::<Vec<_>>())
}

/// Enterprise fleet summary (paid plane). Implementation is not part of the
/// open-source distribution.
#[cfg(feature = "enterprise")]
pub fn fleet_summary(rows: &[Value]) -> Value {
    let _ = rows;
    unimplemented!("fleet aggregation is an enterprise feature")
}

/// Port of the egress block from app.py's `egress_map` endpoint.
/// Keeps rows whose event contains "egress" or "mcp", groups by destination.
pub fn egress(rows: &[Value]) -> Value {
    let mut dest_map: indexmap::IndexMap<String, serde_json::Map<String, Value>> =
        indexmap::IndexMap::new();

    for row in rows {
        let event = row["event"].as_str().unwrap_or("");
        if !event.contains("egress") && !event.contains("mcp") {
            continue;
        }
        let dest = match row.get("destination").and_then(|v| v.as_str()) {
            Some(d) if !d.is_empty() => d.to_string(),
            _ => continue,
        };
        let ts = row["ts"].as_str().unwrap_or("").to_string();
        let verdict = row["verdict"].as_str().unwrap_or("").to_string();

        let entry = dest_map.entry(dest.clone()).or_insert_with(|| {
            let mut m = serde_json::Map::new();
            m.insert("destination".into(), json!(dest));
            m.insert("count".into(), json!(0));
            m.insert("first_seen".into(), json!(ts.clone()));
            m.insert("flagged".into(), json!(false));
            m
        });

        let count = entry["count"].as_i64().unwrap_or(0) + 1;
        entry.insert("count".into(), json!(count));

        if verdict == "deny" {
            entry.insert("flagged".into(), json!(true));
        }

        // Track min first_seen (string comparison works for ISO timestamps)
        let cur_first = entry["first_seen"].as_str().unwrap_or("").to_string();
        if !ts.is_empty() && ts < cur_first {
            entry.insert("first_seen".into(), json!(ts));
        }
    }

    json!(dest_map.values().collect::<Vec<_>>())
}
