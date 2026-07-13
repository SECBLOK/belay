use scanner::analyzers::osv::osv_lookup;

#[test]
fn osv_offline_returns_empty() {
    std::env::set_var("BELAY_OSV_OFFLINE", "1");
    assert!(osv_lookup(&[("left-pad".into(), Some("1.0.0".into()))], "npm", None).is_empty());
    std::env::remove_var("BELAY_OSV_OFFLINE");
}

#[test]
fn osv_empty_packages() {
    assert!(osv_lookup(&[], "npm", None).is_empty());
}

#[test] // PLAIN #[test] NOT #[tokio::test] — reqwest::blocking + httpmock sync = no async-runtime conflict
fn osv_parses_mock_response() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"results":[{"vulns":[{"id":"GHSA-xxxx","database_specific":{"severity":"HIGH"}}]}]}"#);
    });
    let findings = osv_lookup(
        &[("p".into(), Some("1.0.0".into()))],
        "npm",
        Some(&format!("{}/v1/querybatch", server.base_url())),
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "osv.ghsa_xxxx");
    use scanner::types::Severity;
    assert_eq!(findings[0].severity, Severity::High);
    use scanner::types::Decision;
    assert_eq!(findings[0].decision, Decision::Deny);
}
