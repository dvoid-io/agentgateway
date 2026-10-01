use std::collections::HashMap;

use base64::Engine;
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use rstest::rstest;
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use url::form_urlencoded;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::client_auth::{CertificateHeader, RawPrivateKeyJwt};
use super::cross_app_access::{
	CrossAppAccessAuthConfig, CrossAppAccessEndpoint, CrossAppAccessSubjectToken,
};
use super::*;
use crate::http::Body;
use crate::http::auth::JwtSigningAlg;
use crate::http::oauth::{
	CLIENT_ASSERTION_TYPE_JWT_BEARER, GRANT_TYPE_JWT_BEARER, GRANT_TYPE_TOKEN_EXCHANGE,
	TOKEN_TYPE_ACCESS, TOKEN_TYPE_ID, TOKEN_TYPE_ID_JAG, TOKEN_TYPE_JWT,
};
use crate::serdes::FileOrInline;
use crate::types::agent::{BackendTrafficPolicy, SimpleBackendReference, Target};

fn policy_client() -> PolicyClient {
	PolicyClient::new(
		crate::test_helpers::proxymock::setup_proxy_test("{}")
			.unwrap()
			.inputs(),
	)
}

fn token_body() -> serde_json::Value {
	json!({
		"access_token": "upstream-token",
		"token_type": "Bearer",
		"issued_token_type": TOKEN_TYPE_ACCESS,
		"expires_in": 3600,
	})
}

async fn mock_token_endpoint(body: ResponseTemplate) -> MockServer {
	let mock = MockServer::start().await;
	Mock::given(method("POST"))
		.and(path("/token"))
		.respond_with(body)
		.mount(&mock)
		.await;
	mock
}

fn endpoint(mock: &MockServer) -> Arc<SimpleBackendReference> {
	Arc::new(SimpleBackendReference::InlineBackend(Target::Address(
		*mock.address(),
	)))
}

fn base_auth(endpoint: Arc<SimpleBackendReference>) -> OAuthTokenExchangeAuth {
	OAuthTokenExchangeAuth {
		target: SimpleBackendReferenceWithPolicies {
			target: endpoint,
			policies: vec![],
		},
		path: "/token".into(),
		grant_type: OAuthGrantType::TokenExchange,
		subject_token: TokenSpec::default(),
		actor_token: None,
		audiences: vec![],
		scopes: vec![],
		resources: vec![],
		requested_token_type: None,
		client_auth: None,
		additional_params: BTreeMap::new(),
		chained_exchange: None,
		authorization_location: AuthorizationLocation::default(),
		cache: Some(InMemoryTokenCache::default()),
	}
}

fn auth(endpoint: Arc<SimpleBackendReference>) -> OAuthTokenExchangeAuth {
	OAuthTokenExchangeAuth {
		audiences: vec!["https://upstream.example".into()],
		..base_auth(endpoint)
	}
}

fn cross_app_access_endpoint(endpoint: Arc<SimpleBackendReference>) -> CrossAppAccessEndpoint {
	CrossAppAccessEndpoint {
		target: SimpleBackendReferenceWithPolicies {
			target: endpoint,
			policies: vec![],
		},
		path: "/token".into(),
		client_auth: OAuthClientAuth {
			client_id: "gateway-client".into(),
			method: OAuthClientAuthMethod::ClientSecretPost {
				client_secret: None,
			},
		},
	}
}

fn cross_app_access_config(
	idp: Arc<SimpleBackendReference>,
	resource_as: Arc<SimpleBackendReference>,
) -> CrossAppAccessAuthConfig {
	CrossAppAccessAuthConfig {
		identity_provider: cross_app_access_endpoint(idp),
		resource_authorization_server: cross_app_access_endpoint(resource_as),
		audience: "https://resource-as.example".into(),
		resources: vec![],
		scopes: vec!["read".into()],
		access_token_scopes: None,
		subject_token: None,
		cache: Some(InMemoryTokenCache::default()),
	}
}

fn cross_app_access(
	idp: Arc<SimpleBackendReference>,
	resource_as: Arc<SimpleBackendReference>,
) -> CrossAppAccessAuth {
	cross_app_access_config(idp, resource_as).into()
}

fn cross_app_access_with_resources(
	idp: Arc<SimpleBackendReference>,
	resource_as: Arc<SimpleBackendReference>,
	resources: Vec<String>,
) -> CrossAppAccessAuth {
	let mut config = cross_app_access_config(idp, resource_as);
	config.resources = resources;
	config.into()
}

fn exchange_req(subject: &str, token_type: &str) -> ExchangeRequest {
	ExchangeRequest {
		subject_token: subject.to_string().into(),
		subject_token_type: token_type_from_urn(token_type),
		..Default::default()
	}
}

fn token_type_from_urn(token_type: &str) -> OAuthTokenType {
	OAuthTokenType::from_urn(token_type).unwrap()
}

fn jwt_with_claims(claims: &serde_json::Value) -> String {
	let header = BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
	let body = BASE64_URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
	format!("{header}.{body}.sig")
}

const TEST_EC_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgltxBTVDLg7C6vE1T
7OtwJIZ/dpm8ygE2MBTjPCY3hgahRANCAARYzu50EeBrT0rELmTGroaGtn0zdjxL
1lOGr9fGw5wOGcXO0+Gn5F5sIxGyTM0FwnUHFNz2SoixZR5dtxhNc+Lo
-----END PRIVATE KEY-----
";

const TEST_EC_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBEzCBugIBATAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAt0ZXN0LWNsaWVudDAe
Fw0yNjA3MjIwNDE0NThaFw0zNjA3MTkwNDE0NThaMBYxFDASBgNVBAMMC3Rlc3Qt
Y2xpZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWM7udBHga09KxC5kxq6G
hrZ9M3Y8S9ZThq/XxsOcDhnFztPhp+RebCMRskzNBcJ1BxTc9kqIsWUeXbcYTXPi
6DAKBggqhkjOPQQDAgNIADBFAiEAgECXIs3VPrp++0UvPRk1fVXbIo+p19qOQG8e
a/ilbAkCIDgWcfFL3rujLODULW5JbYq9n2xykz5cFTkvLAoAury0
-----END CERTIFICATE-----
";

const TEST_EC_CERT_DER_BASE64: &str = "MIIBEzCBugIBATAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAt0ZXN0LWNsaWVudDAeFw0yNjA3MjIwNDE0NThaFw0zNjA3MTkwNDE0NThaMBYxFDASBgNVBAMMC3Rlc3QtY2xpZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWM7udBHga09KxC5kxq6GhrZ9M3Y8S9ZThq/XxsOcDhnFztPhp+RebCMRskzNBcJ1BxTc9kqIsWUeXbcYTXPi6DAKBggqhkjOPQQDAgNIADBFAiEAgECXIs3VPrp++0UvPRk1fVXbIo+p19qOQG8ea/ilbAkCIDgWcfFL3rujLODULW5JbYq9n2xykz5cFTkvLAoAury0";
const TEST_EC_CERT_SHA256_THUMBPRINT: &str = "LA9ZC2X4Pp6GweXI77YHyao7DPcTLuQKuNmauXVPCcs";

const TEST_MISMATCHED_CERT_PEM: &str =
	include_str!("../../../../tests/common/testdata/root-cert.pem");

const TEST_INVALID_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
bm90IGEgY2VydGlmaWNhdGU=
-----END CERTIFICATE-----
";

fn claims_with_may_act(
	subject_token: &str,
	may_act: serde_json::Value,
) -> crate::http::jwt::Claims {
	let serde_json::Value::Object(inner) = json!({"may_act": may_act}) else {
		unreachable!()
	};
	crate::http::jwt::Claims {
		inner,
		jwt: subject_token.to_string().into(),
	}
}

fn backend_info() -> crate::http::auth::BackendInfo {
	crate::http::auth::BackendInfo {
		target: crate::types::agent::BackendTarget::Invalid,
		call_target: Target::Hostname(crate::strng::new("unused"), 0),
		inputs: crate::test_helpers::proxymock::setup_proxy_test("{}")
			.unwrap()
			.inputs(),
	}
}

fn incoming_request() -> crate::http::Request {
	::http::Request::builder()
		.method(::http::Method::GET)
		.uri("http://upstream/")
		.header(::http::header::AUTHORIZATION, "Bearer subj")
		.body(Body::empty())
		.unwrap()
}

#[test]
fn missing_subject_token_is_invalid_request() {
	let auth = auth(Arc::new(SimpleBackendReference::Invalid));
	let req = ::http::Request::builder()
		.uri("http://upstream/")
		.body(Body::empty())
		.unwrap();

	assert!(matches!(
		auth.build_exchange_request(&req),
		Err(ProxyError::InvalidRequest)
	));
}

async fn sent_form_params(mock: &MockServer) -> HashMap<String, String> {
	let req = &mock.received_requests().await.unwrap()[0];
	form_urlencoded::parse(&req.body).into_owned().collect()
}

fn assert_proto_err_contains(proto: proto::OAuthTokenExchange, expected: &str) {
	let err = OAuthTokenExchangeAuth::from_proto(proto, &mut Diagnostics::default()).unwrap_err();
	assert!(
		matches!(err, ProtoError::Generic(ref m) if m.contains(expected)),
		"expected error containing {expected:?}, got {err:?}"
	);
}

#[test]
fn deserializes_minimal_config() {
	let a: OAuthTokenExchangeAuth =
		serde_json::from_str(r#"{"host": "localhost:8089", "path": "/oauth2/token"}"#).unwrap();
	assert!(matches!(
		a.target.target.as_ref(),
		SimpleBackendReference::InlineBackend(_)
	));
	assert_eq!(a.path, "/oauth2/token");
	assert!(a.cache.is_some());
}

#[test]
fn deserializes_local_cache_config() {
	let a: OAuthTokenExchangeAuth = serde_json::from_str(
		r#"{
			"host": "localhost:8089",
			"cache": {
				"defaultTtl": "42s"
			}
		}"#,
	)
	.unwrap();

	assert!(a.cache.is_some());

	let cfg: TokenCacheConfig = serde_json::from_value(json!({"defaultTtl": "42s"})).unwrap();
	assert_eq!(cfg.default_ttl, Some(Duration::from_secs(42)));
}

#[test]
fn local_cache_config_can_disable_storage() {
	let a: OAuthTokenExchangeAuth = serde_json::from_str(
		r#"{
			"host": "localhost:8089",
			"cache": {
				"maxEntries": 0
			}
		}"#,
	)
	.unwrap();

	assert!(a.cache.is_none());
}

#[test]
fn deserializes_custom_subject_token_type_uri() {
	let auth = serde_json::from_str::<OAuthTokenExchangeAuth>(
		r#"{"host": "localhost:8089", "subjectToken": {"tokenType": "urn:company:domain:human"}}"#,
	)
	.expect("custom absolute URI token type should deserialize");
	assert_eq!(
		auth.subject_token.token_type.as_str(),
		"urn:company:domain:human"
	);
}

#[tokio::test]
async fn fails_closed_on_slow_endpoint() {
	let mock = mock_token_endpoint(
		ResponseTemplate::new(200)
			.set_body_json(token_body())
			.set_delay(Duration::from_secs(2)),
	)
	.await;
	let mut a = base_auth(endpoint(&mock));
	a.target.policies = vec![BackendTrafficPolicy::HTTP(crate::types::backend::HTTP {
		request_timeout: Some(Duration::from_millis(50)),
		..Default::default()
	})];

	let err = fetch_token(
		&policy_client(),
		&a,
		exchange_req("subj", TOKEN_TYPE_ACCESS),
	)
	.await
	.unwrap_err();
	assert!(err.to_string().contains("timeout"), "got: {err}");
}

#[tokio::test]
async fn sends_form_params() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
	let a = auth(endpoint(&mock));

	let tok = fetch_token(
		&policy_client(),
		&a,
		exchange_req("subj-jwt", TOKEN_TYPE_ACCESS),
	)
	.await
	.expect("exchange succeeds");
	assert_eq!(tok.expose_secret(), "upstream-token");

	let pairs = sent_form_params(&mock).await;
	assert_eq!(pairs["grant_type"], GRANT_TYPE_TOKEN_EXCHANGE);
	assert_eq!(pairs["subject_token"], "subj-jwt");
	assert_eq!(pairs["subject_token_type"], TOKEN_TYPE_ACCESS);
	assert_eq!(pairs["audience"], "https://upstream.example");
	for k in ["scope", "resource", "client_id", "requested_token_type"] {
		assert!(!pairs.contains_key(k), "unset param {k} must not be sent");
	}
}

#[tokio::test]
async fn sends_optional_params() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
	let a = OAuthTokenExchangeAuth {
		scopes: vec!["read".into(), "write".into()],
		resources: vec!["https://upstream.example/api".into()],
		requested_token_type: Some(OAuthTokenType::AccessToken),
		client_auth: Some(OAuthClientAuth {
			client_id: "gateway-client".into(),
			method: OAuthClientAuthMethod::ClientSecretPost {
				client_secret: None,
			},
		}),
		..base_auth(endpoint(&mock))
	};

	fetch_token(&policy_client(), &a, exchange_req("subj", TOKEN_TYPE_JWT))
		.await
		.unwrap();
	let pairs = sent_form_params(&mock).await;
	assert!(!pairs.contains_key("audience"));
	assert_eq!(pairs["subject_token_type"], TOKEN_TYPE_JWT);
	assert_eq!(pairs["scope"], "read write");
	assert_eq!(pairs["resource"], "https://upstream.example/api");
	assert_eq!(pairs["requested_token_type"], TOKEN_TYPE_ACCESS);
	assert_eq!(pairs["client_id"], "gateway-client");
	assert!(
		!pairs.contains_key("client_secret"),
		"public client sends no secret"
	);
}

#[tokio::test]
async fn sends_custom_subject_token_type() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
	let a = OAuthTokenExchangeAuth {
		subject_token: TokenSpec {
			source: AuthorizationLocation::default(),
			token_type: token_type_from_urn("urn:company:domain:human"),
		},
		..base_auth(endpoint(&mock))
	};

	fetch_token(
		&policy_client(),
		&a,
		exchange_req("subj", "urn:company:domain:human"),
	)
	.await
	.unwrap();
	let pairs = sent_form_params(&mock).await;
	assert_eq!(pairs["subject_token_type"], "urn:company:domain:human");
	assert!(
		!pairs.contains_key("requested_token_type"),
		"requested_token_type must be omitted when unset"
	);
}

#[tokio::test]
async fn sends_google_sts_workload_identity_form_without_authorization_header() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
	let audience = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pool/providers/provider";
	let a = OAuthTokenExchangeAuth {
		audiences: vec![audience.into()],
		scopes: vec!["https://www.googleapis.com/auth/cloud-platform".into()],
		requested_token_type: Some(OAuthTokenType::AccessToken),
		..base_auth(endpoint(&mock))
	};

	fetch_token(
		&policy_client(),
		&a,
		exchange_req("external-id-token", TOKEN_TYPE_ID),
	)
	.await
	.unwrap();

	let req = &mock.received_requests().await.unwrap()[0];
	assert!(
		req.headers.get("authorization").is_none(),
		"Google STS requests should not send client auth when client_auth is unset"
	);
	let pairs = sent_form_params(&mock).await;
	assert_eq!(pairs["grant_type"], GRANT_TYPE_TOKEN_EXCHANGE);
	assert_eq!(pairs["audience"], audience);
	assert_eq!(
		pairs["scope"],
		"https://www.googleapis.com/auth/cloud-platform"
	);
	assert_eq!(pairs["requested_token_type"], TOKEN_TYPE_ACCESS);
	assert_eq!(pairs["subject_token"], "external-id-token");
	assert_eq!(pairs["subject_token_type"], TOKEN_TYPE_ID);
}

#[rstest]
#[case(TOKEN_TYPE_JWT, "upstream-jwt")]
#[case(TOKEN_TYPE_ID, "upstream-id-token")]
#[tokio::test]
async fn accepts_requested_response_type(
	#[case] requested_token_type: &str,
	#[case] access_token: &str,
) {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(json!({
		"access_token": access_token,
		"token_type": "Bearer",
		"issued_token_type": requested_token_type,
	})))
	.await;
	let a = OAuthTokenExchangeAuth {
		requested_token_type: Some(token_type_from_urn(requested_token_type)),
		..base_auth(endpoint(&mock))
	};

	let tok = fetch_token(
		&policy_client(),
		&a,
		exchange_req("subj", TOKEN_TYPE_ACCESS),
	)
	.await
	.expect("requested response type should be accepted");
	assert_eq!(tok.expose_secret(), access_token);
}

#[tokio::test]
async fn client_secret_basic_uses_authorization_header() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
	let a = OAuthTokenExchangeAuth {
		client_auth: Some(OAuthClientAuth {
			client_id: "gw client".into(),
			method: OAuthClientAuthMethod::ClientSecretBasic {
				client_secret: "s3cr3t".into(),
			},
		}),
		..base_auth(endpoint(&mock))
	};

	fetch_token(
		&policy_client(),
		&a,
		exchange_req("subj", TOKEN_TYPE_ACCESS),
	)
	.await
	.unwrap();

	let req = &mock.received_requests().await.unwrap()[0];
	let header = req.headers["authorization"].to_str().unwrap();
	assert_eq!(
		header,
		format!("Basic {}", BASE64_STANDARD.encode("gw+client:s3cr3t"))
	);
	let pairs = sent_form_params(&mock).await;
	assert!(
		!pairs.contains_key("client_id"),
		"basic auth keeps creds out of the body"
	);
	assert!(!pairs.contains_key("client_secret"));
}

#[tokio::test]
async fn client_secret_post_uses_form_body() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
	let a = OAuthTokenExchangeAuth {
		client_auth: Some(OAuthClientAuth {
			client_id: "gateway-client".into(),
			method: OAuthClientAuthMethod::ClientSecretPost {
				client_secret: Some("s3cr3t".into()),
			},
		}),
		..base_auth(endpoint(&mock))
	};

	fetch_token(
		&policy_client(),
		&a,
		exchange_req("subj", TOKEN_TYPE_ACCESS),
	)
	.await
	.unwrap();

	let req = &mock.received_requests().await.unwrap()[0];
	assert!(req.headers.get("authorization").is_none());
	let pairs = sent_form_params(&mock).await;
	assert_eq!(pairs["client_id"], "gateway-client");
	assert_eq!(pairs["client_secret"], "s3cr3t");
}

#[tokio::test]
async fn jwt_bearer_sends_assertion() {
	// RFC 7523 response: a plain RFC 6749 body with no issued_token_type.
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(json!({
		"access_token": "upstream-token",
		"token_type": "Bearer",
	})))
	.await;
	let a = OAuthTokenExchangeAuth {
		grant_type: OAuthGrantType::JwtBearer,
		..base_auth(endpoint(&mock))
	};

	let tok = fetch_token(
		&policy_client(),
		&a,
		exchange_req("the-jwt", TOKEN_TYPE_ACCESS),
	)
	.await
	.expect("jwt-bearer exchange succeeds");
	assert_eq!(tok.expose_secret(), "upstream-token");

	let pairs = sent_form_params(&mock).await;
	assert_eq!(pairs["grant_type"], GRANT_TYPE_JWT_BEARER);
	assert_eq!(pairs["assertion"], "the-jwt");
	for k in [
		"subject_token",
		"subject_token_type",
		"requested_token_type",
	] {
		assert!(!pairs.contains_key(k), "jwt-bearer must not send {k}");
	}
}

#[tokio::test]
async fn id_jag_chain_exchanges_two_legs_and_caches_final_token() {
	let idp = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(json!({
		"access_token": "id-jag-assertion",
		"token_type": "N_A",
		"issued_token_type": TOKEN_TYPE_ID_JAG,
		"expires_in": 120,
	})))
	.await;
	let resource_as = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(json!({
		"access_token": "resource-access-token",
		"token_type": "Bearer",
		"expires_in": 3600,
	})))
	.await;
	let identity = cross_app_access_with_resources(
		endpoint(&idp),
		endpoint(&resource_as),
		vec!["https://api.resource-as.example/chat".into()],
	);
	let a = identity.oauth_token_exchange();

	for _ in 0..2 {
		let tok = fetch_token(&policy_client(), a, exchange_req("id-token", TOKEN_TYPE_ID))
			.await
			.expect("id-jag chain succeeds");
		assert_eq!(tok.expose_secret(), "resource-access-token");
	}

	let idp_requests = idp.received_requests().await.unwrap();
	assert_eq!(idp_requests.len(), 1, "root cache stores the final bearer");
	let idp_pairs: HashMap<String, String> = form_urlencoded::parse(&idp_requests[0].body)
		.into_owned()
		.collect();
	assert_eq!(idp_pairs["requested_token_type"], TOKEN_TYPE_ID_JAG);
	assert_eq!(idp_pairs["audience"], "https://resource-as.example");
	assert_eq!(idp_pairs["subject_token_type"], TOKEN_TYPE_ID);
	assert_eq!(idp_pairs["scope"], "read");
	assert_eq!(
		idp_pairs["resource"], "https://api.resource-as.example/chat",
		"idp ID-JAG request must carry the target resource"
	);

	let resource_requests = resource_as.received_requests().await.unwrap();
	assert_eq!(resource_requests.len(), 1);
	let resource_pairs: HashMap<String, String> = form_urlencoded::parse(&resource_requests[0].body)
		.into_owned()
		.collect();
	assert_eq!(resource_pairs["grant_type"], GRANT_TYPE_JWT_BEARER);
	assert_eq!(resource_pairs["assertion"], "id-jag-assertion");
	// The jwt-bearer leg sends `scope` to select the access-token scopes, but omits `resource`
	// (bound via the ID-JAG claims).
	assert_eq!(resource_pairs["scope"], "read");
	assert!(!resource_pairs.contains_key("resource"));
}

#[tokio::test]
async fn id_jag_chain_omits_explicitly_empty_access_token_scopes() {
	let idp = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(json!({
		"access_token": "id-jag-assertion",
		"token_type": "N_A",
		"issued_token_type": TOKEN_TYPE_ID_JAG,
	})))
	.await;
	let resource_as = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(json!({
		"access_token": "resource-access-token",
		"token_type": "Bearer",
	})))
	.await;
	let mut config = cross_app_access_config(endpoint(&idp), endpoint(&resource_as));
	config.access_token_scopes = Some(vec![]);
	let identity = CrossAppAccessAuth::from(config);

	fetch_token(
		&policy_client(),
		identity.oauth_token_exchange(),
		exchange_req("id-token", TOKEN_TYPE_ID),
	)
	.await
	.expect("id-jag chain succeeds");

	let idp_pairs = sent_form_params(&idp).await;
	assert_eq!(idp_pairs["scope"], "read");
	let resource_pairs = sent_form_params(&resource_as).await;
	assert!(
		!resource_pairs.contains_key("scope"),
		"empty accessTokenScopes must omit scope"
	);
}

#[tokio::test]
async fn id_jag_intermediate_rejects_bearer_token_type() {
	let idp = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(json!({
		"access_token": "id-jag-assertion",
		"token_type": "Bearer",
		"issued_token_type": TOKEN_TYPE_ID_JAG,
	})))
	.await;
	let resource_as =
		mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
	let identity = cross_app_access(endpoint(&idp), endpoint(&resource_as));
	let a = identity.oauth_token_exchange();

	let err = fetch_token(&policy_client(), a, exchange_req("subj", TOKEN_TYPE_ID))
		.await
		.unwrap_err();
	assert!(
		err
			.to_string()
			.contains("unsupported token_type for id-jag: Bearer"),
		"got: {err}"
	);
	assert!(resource_as.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn id_jag_chained_exchange_client_error_is_upstream_failure() {
	let idp = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(json!({
		"access_token": "id-jag-assertion",
		"token_type": "N_A",
		"issued_token_type": TOKEN_TYPE_ID_JAG,
	})))
	.await;
	let resource_as = mock_token_endpoint(
		ResponseTemplate::new(400)
			.set_body_string(r#"{"error":"invalid_grant","error_description":"issuer not trusted"}"#),
	)
	.await;
	let identity = cross_app_access(endpoint(&idp), endpoint(&resource_as));
	let a = identity.oauth_token_exchange();

	let err = fetch_token(&policy_client(), a, exchange_req("subj", TOKEN_TYPE_ID))
		.await
		.unwrap_err();
	assert!(matches!(err, FetchError::Upstream(_)), "got: {err:?}");
	let msg = err.to_string();
	assert!(msg.contains("chained token exchange returned status 400"));
	assert!(!msg.contains("invalid_grant"), "got: {msg}");
	assert!(!msg.contains("issuer not trusted"), "got: {msg}");
}

#[tokio::test]
async fn private_key_jwt_sends_client_assertion_form_fields() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
	let private_key = PrivateKeyJwt::try_from(RawPrivateKeyJwt {
		signing_key: Some(SecretString::from(TEST_EC_PRIVATE_KEY_PEM)),
		signer: None,
		certificate: Some(FileOrInline::Inline(TEST_EC_CERT_PEM.to_string()).into()),
		certificate_header: Some(CertificateHeader::X5c),
		alg: JwtSigningAlg::Es256,
		kid: Some("kid-1".into()),
		assertion_audience: "https://issuer.example/token".into(),
	})
	.unwrap();
	let a = OAuthTokenExchangeAuth {
		client_auth: Some(OAuthClientAuth {
			client_id: "gateway-client".into(),
			method: OAuthClientAuthMethod::PrivateKeyJwt(private_key),
		}),
		..base_auth(endpoint(&mock))
	};

	fetch_token(
		&policy_client(),
		&a,
		exchange_req("subj", TOKEN_TYPE_ACCESS),
	)
	.await
	.unwrap();

	let req = &mock.received_requests().await.unwrap()[0];
	assert!(req.headers.get("authorization").is_none());
	let pairs = sent_form_params(&mock).await;
	assert_eq!(pairs["client_id"], "gateway-client");
	assert_eq!(
		pairs["client_assertion_type"],
		CLIENT_ASSERTION_TYPE_JWT_BEARER
	);
	#[derive(serde::Deserialize)]
	struct AssertionClaims {
		iss: String,
		sub: String,
		aud: String,
		jti: String,
		nbf: u64,
		iat: u64,
		exp: u64,
	}
	let claims: AssertionClaims = decode_unverified_jwt_claims(&pairs["client_assertion"]).unwrap();
	let header = jsonwebtoken::decode_header(&pairs["client_assertion"]).unwrap();
	assert_eq!(header.x5c, Some(vec![TEST_EC_CERT_DER_BASE64.to_string()]));
	assert_eq!(header.x5t_s256, None);
	assert_eq!(claims.iss, "gateway-client");
	assert_eq!(claims.sub, "gateway-client");
	assert_eq!(claims.aud, "https://issuer.example/token");
	assert!(!claims.jti.is_empty());
	assert_eq!(claims.nbf, claims.iat);
	assert_eq!(claims.exp - claims.iat, 310);
}

#[test]
fn private_key_jwt_debug_redacts_key_and_certificate() {
	let raw = RawPrivateKeyJwt {
		signing_key: Some(SecretString::from(TEST_EC_PRIVATE_KEY_PEM)),
		signer: None,
		certificate: Some(FileOrInline::Inline(TEST_EC_CERT_PEM.to_string()).into()),
		certificate_header: Some(CertificateHeader::X5c),
		alg: JwtSigningAlg::Es256,
		kid: Some("kid-1".into()),
		assertion_audience: "https://issuer.example/token".into(),
	};
	let raw_debug = format!("{raw:?}");
	assert!(!raw_debug.contains(TEST_EC_PRIVATE_KEY_PEM));
	assert!(!raw_debug.contains(TEST_EC_CERT_PEM));
	assert!(raw_debug.contains("[REDACTED]"));

	let private_key = PrivateKeyJwt::try_from(raw).unwrap();
	let debug = format!("{private_key:?}");
	assert!(!debug.contains(TEST_EC_PRIVATE_KEY_PEM));
	assert!(!debug.contains(TEST_EC_CERT_DER_BASE64));
	assert!(debug.contains("x5c: Some(\"[REDACTED]\")"));
	assert!(debug.contains("alg: Es256"));
}

#[tokio::test]
async fn private_key_jwt_sets_x5t_s256_header() {
	let private_key = serde_json::from_value::<PrivateKeyJwt>(json!({
		"signingKey": TEST_EC_PRIVATE_KEY_PEM,
		"certificate": TEST_EC_CERT_PEM,
		"certificateHeader": "x5t#S256",
		"alg": "ES256",
		"assertionAudience": "https://issuer.example/token",
	}))
	.unwrap();

	let assertion = sign_client_assertion(&policy_client(), "gateway-client", &private_key)
		.await
		.unwrap();
	let header = jsonwebtoken::decode_header(&assertion).unwrap();
	assert_eq!(header.x5c, None);
	assert_eq!(
		header.x5t_s256.as_deref(),
		Some(TEST_EC_CERT_SHA256_THUMBPRINT)
	);
}

#[tokio::test]
async fn private_key_jwt_signs_with_ps256() {
	let signing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
	let public_key = signing_key.public_key_pem();
	let private_key = PrivateKeyJwt::try_from(RawPrivateKeyJwt {
		signing_key: Some(SecretString::from(signing_key.serialize_pem())),
		signer: None,
		certificate: None,
		certificate_header: None,
		alg: JwtSigningAlg::Ps256,
		kid: None,
		assertion_audience: "https://issuer.example/token".into(),
	})
	.unwrap();

	let assertion = sign_client_assertion(&policy_client(), "gateway-client", &private_key)
		.await
		.unwrap();
	assert_eq!(
		jsonwebtoken::decode_header(&assertion).unwrap().alg,
		jsonwebtoken::Algorithm::PS256
	);
	let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::PS256);
	validation.set_audience(&["https://issuer.example/token"]);
	validation.set_issuer(&["gateway-client"]);
	jsonwebtoken::decode::<serde_json::Value>(
		&assertion,
		&jsonwebtoken::DecodingKey::from_rsa_pem(public_key.as_bytes()).unwrap(),
		&validation,
	)
	.unwrap();
}

#[rstest]
#[case::missing_header(true, false, "certificate_header is required when certificate is set")]
#[case::missing_certificate(false, true, "certificate is required when certificate_header is set")]
fn private_key_jwt_requires_certificate_and_header_together(
	#[case] with_certificate: bool,
	#[case] with_certificate_header: bool,
	#[case] expected: &str,
) {
	let err = PrivateKeyJwt::try_from(RawPrivateKeyJwt {
		signing_key: Some(SecretString::from(TEST_EC_PRIVATE_KEY_PEM)),
		signer: None,
		certificate: with_certificate
			.then(|| FileOrInline::Inline(TEST_EC_CERT_PEM.to_string()))
			.map(Into::into),
		certificate_header: with_certificate_header.then_some(CertificateHeader::X5c),
		alg: JwtSigningAlg::Es256,
		kid: None,
		assertion_audience: "https://issuer.example/token".into(),
	})
	.expect_err("certificate and certificate_header must be configured together");
	assert!(err.contains(expected), "got: {err}");
}

#[test]
fn private_key_jwt_rejects_bad_key_at_deserialize_time() {
	let err = serde_json::from_str::<OAuthTokenExchangeAuth>(
		r#"{
			"host": "localhost:8089",
			"clientAuth": {
				"clientId": "gateway-client",
				"method": "privateKeyJwt",
				"signingKey": "not a key",
				"alg": "ES256",
				"assertionAudience": "https://issuer.example/token"
			}
		}"#,
	)
	.expect_err("bad key must fail during config load");
	assert!(err.to_string().contains("signing_key"), "got: {err}");
}

#[test]
fn private_key_jwt_rejects_non_certificate_pem_at_deserialize_time() {
	let config = format!(
		r#"{{
			"host": "localhost:8089",
			"clientAuth": {{
				"clientId": "gateway-client",
				"method": "privateKeyJwt",
				"signingKey": {signing_key:?},
				"certificate": {certificate:?},
				"certificateHeader": "x5c",
				"alg": "ES256",
				"assertionAudience": "https://issuer.example/token"
			}}
		}}"#,
		signing_key = TEST_EC_PRIVATE_KEY_PEM,
		certificate = TEST_EC_PRIVATE_KEY_PEM,
	);
	let err = serde_json::from_str::<OAuthTokenExchangeAuth>(&config)
		.expect_err("non-certificate PEM must fail during config load");
	assert!(
		err.to_string().contains("expected CERTIFICATE"),
		"got: {err}"
	);
}

#[test]
fn private_key_jwt_rejects_invalid_certificate_in_chain() {
	let err = PrivateKeyJwt::try_from(RawPrivateKeyJwt {
		signing_key: Some(SecretString::from(TEST_EC_PRIVATE_KEY_PEM)),
		signer: None,
		certificate: Some(
			FileOrInline::Inline(format!("{TEST_EC_CERT_PEM}{TEST_INVALID_CERT_PEM}")).into(),
		),
		certificate_header: Some(CertificateHeader::X5c),
		alg: JwtSigningAlg::Es256,
		kid: None,
		assertion_audience: "https://issuer.example/token".into(),
	})
	.expect_err("every x5c entry must be a valid X.509 certificate");
	assert!(
		err.contains("failed to parse oauth private_key_jwt certificate"),
		"got: {err}"
	);
}

#[test]
fn private_key_jwt_warns_but_accepts_mismatched_certificate() {
	PrivateKeyJwt::try_from(RawPrivateKeyJwt {
		signing_key: Some(SecretString::from(TEST_EC_PRIVATE_KEY_PEM)),
		signer: None,
		certificate: Some(FileOrInline::Inline(TEST_MISMATCHED_CERT_PEM.to_string()).into()),
		certificate_header: Some(CertificateHeader::X5c),
		alg: JwtSigningAlg::Es256,
		kid: None,
		assertion_audience: "https://issuer.example/token".into(),
	})
	.expect("a certificate mismatch must remain non-fatal");
}

#[test]
fn client_auth_rejects_unknown_fields() {
	let err = serde_json::from_str::<OAuthTokenExchangeAuth>(
		r#"{
			"host": "localhost:8089",
			"clientAuth": {
				"clientId": "gateway-client",
				"method": "clientSecretPost",
				"clientSecret": "secret",
				"clientSecrett": "typo"
			}
		}"#,
	)
	.expect_err("unknown clientAuth fields must fail during config load");
	assert!(
		err.to_string().contains("did not match any variant"),
		"got: {err}"
	);
}

#[test]
fn client_auth_defaults_to_basic_when_method_is_omitted() {
	let auth = serde_json::from_str::<OAuthTokenExchangeAuth>(
		r#"{
			"host": "localhost:8089",
			"clientAuth": {
				"clientId": "gateway-client",
				"clientSecret": "secret"
			}
		}"#,
	)
	.unwrap();
	let client_auth = auth.client_auth.expect("client auth");
	assert_eq!(client_auth.client_id, "gateway-client");
	assert!(matches!(
		client_auth.method,
		OAuthClientAuthMethod::ClientSecretBasic { .. }
	));
}

#[test]
fn cross_app_access_endpoint_rejects_unknown_fields() {
	let err = serde_json::from_str::<CrossAppAccessAuth>(
		r#"{
				"identityProvider": {
					"host": "idp.example.com:443",
					"clientAuth": {
						"clientId": "gateway-at-idp",
						"method": "clientSecretPost"
					}
				},
				"resourceAuthorizationServer": {
					"host": "chat.example.com:443",
					"tokenEndpointPat": "/oauth2/token",
					"clientAuth": {
						"clientId": "gateway-at-chat",
						"method": "clientSecretPost"
					}
				},
				"audience": "https://chat.example.com/"
			}"#,
	)
	.expect_err("unknown endpoint fields must fail during config load");
	assert!(err.to_string().contains("unknown field"), "got: {err}");
}

fn cross_app_access_local_config() -> CrossAppAccessAuth {
	let auth: CrossAppAccessAuth = serde_json::from_str(
		r#"{
				"identityProvider": {
					"host": "idp.example.com:443",
					"path": "/oauth2/token",
					"clientAuth": {
						"clientId": "gateway-at-idp",
						"method": "clientSecretBasic",
						"clientSecret": "mock-idp-client-secret"
					}
				},
				"resourceAuthorizationServer": {
					"host": "chat.example.com:443",
					"path": "/oauth2/token",
					"clientAuth": {
						"clientId": "gateway-at-chat",
						"method": "clientSecretBasic",
						"clientSecret": "mock-resource-authorization-server-client-secret"
					}
				},
				"audience": "https://chat.example.com/",
				"resources": ["https://api.chat.example.com/"],
				"scopes": ["chat.read", "chat.history"],
				"subjectToken": {
					"source": { "expression": "jwt.the_id_token" }
				},
				"cache": {
					"defaultTtl": "1h"
				}
			}"#,
	)
	.unwrap();
	auth.validate_load().unwrap();
	auth
}

#[test]
fn deserializes_cross_app_access_local_config_shape() {
	let auth = cross_app_access_local_config();
	let oauth = auth.oauth_token_exchange();
	assert_eq!(oauth.requested_token_type, Some(OAuthTokenType::IdJag));
	assert!(matches!(
		&oauth.subject_token.source,
		AuthorizationLocation::Expression(expression)
			if expression.original_expression == "jwt.the_id_token"
	));
	assert_eq!(oauth.subject_token.token_type, OAuthTokenType::IdToken);
	// The IdP token-exchange leg carries the configured resource (draft requires it there).
	assert_eq!(oauth.resources, ["https://api.chat.example.com/"]);
	// The jwt-bearer leg carries `scope` (selects access-token scopes) but not `resource`.
	let chained_exchange = oauth.chained_exchange.as_ref().expect("chained exchange");
	assert!(chained_exchange.resources.is_empty());
	assert_eq!(chained_exchange.scopes, ["chat.read", "chat.history"]);
}

#[rstest]
#[case::absent(None, &["read"])]
#[case::empty(Some(vec![]), &[])]
#[case::override_scopes(Some(vec!["backend.read".into()]), &["backend.read"])]
fn cross_app_access_resolves_access_token_scopes(
	#[case] access_token_scopes: Option<Vec<String>>,
	#[case] expected: &[&str],
) {
	let mut config = cross_app_access_config(
		Arc::new(SimpleBackendReference::Invalid),
		Arc::new(SimpleBackendReference::Invalid),
	);
	config.access_token_scopes = access_token_scopes;

	let auth = CrossAppAccessAuth::from(config);
	assert_eq!(
		auth
			.oauth_token_exchange()
			.chained_exchange
			.as_ref()
			.expect("chained exchange")
			.scopes,
		expected
	);
}

#[test]
fn cross_app_access_subject_token_source_override() {
	let mut config = cross_app_access_config(
		Arc::new(SimpleBackendReference::Invalid),
		Arc::new(SimpleBackendReference::Invalid),
	);

	// Unset: the id_token is read from the Authorization Bearer header.
	let auth = CrossAppAccessAuth::from(config.clone());
	let subject_token = &auth.oauth_token_exchange().subject_token;
	assert!(matches!(
		&subject_token.source,
		AuthorizationLocation::Header { name, .. } if name == ::http::header::AUTHORIZATION
	));
	assert_eq!(subject_token.token_type, OAuthTokenType::IdToken);

	// Overridden source; the exchange still declares an id_token subject.
	config.subject_token = Some(CrossAppAccessSubjectToken {
		source: serde_json::from_str(r#"{"expression": "jwt.the_id_token"}"#).unwrap(),
		..Default::default()
	});
	let auth = CrossAppAccessAuth::from(config);
	let subject_token = &auth.oauth_token_exchange().subject_token;
	let AuthorizationLocation::Expression(expr) = &subject_token.source else {
		panic!(
			"expected an expression source, got {:?}",
			subject_token.source
		);
	};
	assert_eq!(expr.original_expression, "jwt.the_id_token");
	assert_eq!(subject_token.token_type, OAuthTokenType::IdToken);
}

#[rstest]
#[case::access_token(TOKEN_TYPE_ACCESS)]
#[case::custom("urn:company:domain:human")]
fn cross_app_access_subject_token_type_override(#[case] token_type: &str) {
	let mut config = cross_app_access_config(
		Arc::new(SimpleBackendReference::Invalid),
		Arc::new(SimpleBackendReference::Invalid),
	);
	let subject_token: CrossAppAccessSubjectToken =
		serde_json::from_value(json!({ "tokenType": token_type })).unwrap();
	assert_eq!(
		serde_json::to_value(&subject_token).unwrap()["tokenType"],
		token_type
	);
	config.subject_token = Some(subject_token);

	let auth = CrossAppAccessAuth::from(config);
	assert_eq!(
		auth
			.oauth_token_exchange()
			.subject_token
			.token_type
			.as_str(),
		token_type
	);
}

#[test]
fn cross_app_access_rejects_id_jag_subject_token_type() {
	let mut config = cross_app_access_config(
		Arc::new(SimpleBackendReference::Invalid),
		Arc::new(SimpleBackendReference::Invalid),
	);
	config.subject_token = Some(CrossAppAccessSubjectToken {
		token_type: OAuthTokenType::IdJag,
		..Default::default()
	});

	let err = CrossAppAccessAuth::from(config)
		.validate_load()
		.unwrap_err();
	assert!(err.contains("subjectToken tokenType id-jag"));
}

#[test]
fn serializes_cross_app_access_local_config_shape() {
	let serialized = serde_json::to_value(cross_app_access_local_config()).unwrap();
	assert!(serialized.get("identityProvider").is_some());
	assert!(serialized.get("resourceAuthorizationServer").is_some());
	assert_eq!(serialized["audience"], "https://chat.example.com/");
	assert_eq!(
		serialized["resources"],
		json!(["https://api.chat.example.com/"])
	);
	assert_eq!(serialized["scopes"], json!(["chat.read", "chat.history"]));
	assert!(serialized.get("accessTokenScopes").is_none());
	assert_eq!(serialized["identityProvider"]["path"], "/oauth2/token");
	assert_eq!(
		serialized["subjectToken"]["source"],
		json!({ "expression": "jwt.the_id_token" })
	);
	assert_eq!(
		serialized["identityProvider"]["clientAuth"]["clientId"],
		"gateway-at-idp"
	);
	assert_eq!(
		serialized["resourceAuthorizationServer"]["clientAuth"]["clientId"],
		"gateway-at-chat"
	);
	assert!(serialized.get("oauthTokenExchange").is_none());
	assert!(serialized.get("cache").is_none());
}

#[rstest]
#[case::unset(None, None)]
#[case::matching(Some(vec!["read".into()]), None)]
#[case::empty(Some(vec![]), Some(json!([])))]
#[case::different(Some(vec!["backend.read".into()]), Some(json!(["backend.read"])))]
fn serializes_cross_app_access_scope_override(
	#[case] access_token_scopes: Option<Vec<String>>,
	#[case] expected: Option<serde_json::Value>,
) {
	let backend = || Arc::new(SimpleBackendReference::Invalid);
	let mut config = cross_app_access_config(backend(), backend());
	config.access_token_scopes = access_token_scopes;

	let serialized = serde_json::to_value(CrossAppAccessAuth::from(config)).unwrap();
	assert_eq!(serialized.get("accessTokenScopes"), expected.as_ref());
}

#[test]
fn serializes_cross_app_access_subject_token() {
	let backend = || {
		Arc::new(SimpleBackendReference::InlineBackend(Target::Hostname(
			crate::strng::new("idp.example.com"),
			443,
		)))
	};
	let mut config = cross_app_access_config(backend(), backend());

	// The default Bearer-header source is spelled out on the way back to config.
	let serialized = serde_json::to_value(CrossAppAccessAuth::from(config.clone())).unwrap();
	assert_eq!(
		serialized["subjectToken"]["source"],
		json!({ "header": { "name": "authorization", "prefix": "Bearer " } })
	);

	// A configured source is preserved on the way back to config.
	config.subject_token = Some(CrossAppAccessSubjectToken {
		source: serde_json::from_str(r#"{"expression": "jwt.the_id_token"}"#).unwrap(),
		token_type: OAuthTokenType::AccessToken,
	});
	let serialized = serde_json::to_value(CrossAppAccessAuth::from(config)).unwrap();
	assert_eq!(
		serialized["subjectToken"],
		json!({
			"source": { "expression": "jwt.the_id_token" },
			"tokenType": TOKEN_TYPE_ACCESS
		})
	);
}

#[rstest]
#[case::header(r#"{"header":{"name":"x-subject-token","prefix":"Token "}}"#)]
#[case::query_parameter(r#"{"queryParameter":{"name":"subject_token"}}"#)]
#[case::cookie(r#"{"cookie":{"name":"subject_token"}}"#)]
#[case::expression(r#"{"expression":"jwt.the_id_token"}"#)]
fn round_trips_cross_app_access_subject_token_source(#[case] source: &str) {
	let backend = || {
		Arc::new(SimpleBackendReference::InlineBackend(Target::Hostname(
			crate::strng::new("idp.example.com"),
			443,
		)))
	};
	let mut config = cross_app_access_config(backend(), backend());
	config.subject_token = Some(CrossAppAccessSubjectToken {
		source: serde_json::from_str(source).unwrap(),
		..Default::default()
	});

	let serialized = serde_json::to_value(CrossAppAccessAuth::from(config)).unwrap();
	assert_eq!(
		serialized["subjectToken"]["source"],
		serde_json::from_str::<serde_json::Value>(source).unwrap()
	);

	let mut round_trip_config = cross_app_access_config(backend(), backend());
	round_trip_config.subject_token =
		Some(serde_json::from_value(serialized["subjectToken"].clone()).unwrap());
	let round_tripped = CrossAppAccessAuth::from(round_trip_config);
	let round_tripped =
		serde_json::to_value(round_tripped).expect("round-tripped config should serialize");
	assert_eq!(
		round_tripped["subjectToken"]["source"],
		serialized["subjectToken"]["source"]
	);
}

#[test]
fn cross_app_access_validate_load_preserves_path_prefix() {
	let mut config = cross_app_access_config(
		Arc::new(SimpleBackendReference::Invalid),
		Arc::new(SimpleBackendReference::Invalid),
	);
	config.resource_authorization_server.path = "oauth2/token".into();
	let auth = CrossAppAccessAuth::from(config);

	let err = auth.validate_load().expect_err("invalid path should fail");
	assert!(
		err.contains("crossAppAccess.resourceAuthorizationServer.path"),
		"got: {err}"
	);
}

#[rstest]
#[case::default("", OAuthTokenType::IdToken)]
#[case::access_token(TOKEN_TYPE_ACCESS, OAuthTokenType::AccessToken)]
#[case::custom(
	"urn:company:domain:human",
	OAuthTokenType::Custom("urn:company:domain:human".into())
)]
fn cross_app_access_from_proto_derives_oauth_chain(
	#[case] token_type: &str,
	#[case] expected_token_type: OAuthTokenType,
) {
	let auth = CrossAppAccessAuth::from_proto(
		proto::CrossAppAccessAuth {
			identity_provider: Some(proto::cross_app_access_auth::Endpoint {
				token_endpoint: Some(proto::BackendReference {
					kind: Some(proto::backend_reference::Kind::Backend(
						"default/idp".to_string(),
					)),
					..Default::default()
				}),
				token_endpoint_path: Some("/idp/token".to_string()),
				client_auth: Some(proto::OAuthClientAuth {
					client_id: "gateway-at-idp".to_string(),
					method: proto::o_auth_client_auth::Method::ClientSecretPost as i32,
					..Default::default()
				}),
				inline_policies: vec![],
			}),
			resource_authorization_server: Some(proto::cross_app_access_auth::Endpoint {
				token_endpoint: Some(proto::BackendReference {
					kind: Some(proto::backend_reference::Kind::Backend(
						"default/resource-as".to_string(),
					)),
					..Default::default()
				}),
				token_endpoint_path: Some("/resource/token".to_string()),
				client_auth: Some(proto::OAuthClientAuth {
					client_id: "gateway-at-resource".to_string(),
					method: proto::o_auth_client_auth::Method::ClientSecretPost as i32,
					..Default::default()
				}),
				inline_policies: vec![],
			}),
			audience: "https://resource.example.com".to_string(),
			resources: vec!["https://api.example.com".to_string()],
			scopes: vec!["read".to_string()],
			access_token_scopes: None,
			subject_token: Some(proto::cross_app_access_auth::SubjectToken {
				source: Some(proto::AuthorizationLocation {
					kind: Some(proto::authorization_location::Kind::Expression(
						"jwt.the_id_token".to_string(),
					)),
				}),
				token_type: token_type.to_string(),
			}),
			cache: None,
		},
		&mut Diagnostics::default(),
	)
	.unwrap();

	let oauth = auth.oauth_token_exchange();
	assert_eq!(oauth.requested_token_type, Some(OAuthTokenType::IdJag));
	assert_eq!(oauth.subject_token.token_type, expected_token_type);
	assert!(matches!(
		&oauth.subject_token.source,
		AuthorizationLocation::Expression(expression)
			if expression.original_expression == "jwt.the_id_token"
	));
	assert_eq!(oauth.audiences, ["https://resource.example.com"]);
	assert_eq!(oauth.resources, ["https://api.example.com"]);
	let chained_exchange = oauth.chained_exchange.as_ref().expect("chained exchange");
	assert_eq!(chained_exchange.scopes, ["read"]);
	assert!(chained_exchange.resources.is_empty());
}

#[rstest]
#[case::absent(None, &["read"])]
#[case::empty(
	Some(proto::cross_app_access_auth::ScopeOverride { values: vec![] }),
	&[]
)]
#[case::override_scopes(
	Some(proto::cross_app_access_auth::ScopeOverride {
		values: vec!["backend.read".into()],
	}),
	&["backend.read"]
)]
fn cross_app_access_from_proto_resolves_access_token_scopes(
	#[case] access_token_scopes: Option<proto::cross_app_access_auth::ScopeOverride>,
	#[case] expected: &[&str],
) {
	let auth = CrossAppAccessAuth::from_proto(
		proto::CrossAppAccessAuth {
			identity_provider: Some(proto::cross_app_access_auth::Endpoint {
				token_endpoint: Some(proto::BackendReference {
					kind: Some(proto::backend_reference::Kind::Backend(
						"default/idp".into(),
					)),
					..Default::default()
				}),
				client_auth: Some(proto::OAuthClientAuth {
					client_id: "gateway-at-idp".into(),
					method: proto::o_auth_client_auth::Method::ClientSecretPost as i32,
					..Default::default()
				}),
				..Default::default()
			}),
			resource_authorization_server: Some(proto::cross_app_access_auth::Endpoint {
				token_endpoint: Some(proto::BackendReference {
					kind: Some(proto::backend_reference::Kind::Backend(
						"default/resource-as".into(),
					)),
					..Default::default()
				}),
				client_auth: Some(proto::OAuthClientAuth {
					client_id: "gateway-at-resource".into(),
					method: proto::o_auth_client_auth::Method::ClientSecretPost as i32,
					..Default::default()
				}),
				..Default::default()
			}),
			audience: "https://resource.example.com".into(),
			scopes: vec!["read".into()],
			access_token_scopes,
			..Default::default()
		},
		&mut Diagnostics::default(),
	)
	.unwrap();

	assert_eq!(
		auth
			.oauth_token_exchange()
			.chained_exchange
			.as_ref()
			.expect("chained exchange")
			.scopes,
		expected
	);
}

#[test]
fn cross_app_access_from_proto_rejects_malformed_subject_token_type() {
	let err = CrossAppAccessAuth::from_proto(
		proto::CrossAppAccessAuth {
			subject_token: Some(proto::cross_app_access_auth::SubjectToken {
				token_type: "https://".to_string(),
				..Default::default()
			}),
			..Default::default()
		},
		&mut Diagnostics::default(),
	)
	.unwrap_err();

	assert!(
		err
			.to_string()
			.contains("crossAppAccess.subjectToken.tokenType")
	);
}

#[test]
fn cross_app_access_from_proto_requires_token_endpoint() {
	let err = CrossAppAccessAuth::from_proto(
		proto::CrossAppAccessAuth {
			identity_provider: Some(proto::cross_app_access_auth::Endpoint {
				client_auth: Some(proto::OAuthClientAuth {
					client_id: "gateway-at-idp".to_string(),
					method: proto::o_auth_client_auth::Method::ClientSecretPost as i32,
					..Default::default()
				}),
				..Default::default()
			}),
			resource_authorization_server: Some(proto::cross_app_access_auth::Endpoint {
				token_endpoint: Some(proto::BackendReference {
					kind: Some(proto::backend_reference::Kind::Backend(
						"default/resource-as".to_string(),
					)),
					..Default::default()
				}),
				client_auth: Some(proto::OAuthClientAuth {
					client_id: "gateway-at-resource".to_string(),
					method: proto::o_auth_client_auth::Method::ClientSecretPost as i32,
					..Default::default()
				}),
				..Default::default()
			}),
			..Default::default()
		},
		&mut Diagnostics::default(),
	)
	.unwrap_err();

	assert!(matches!(err, ProtoError::MissingRequiredField));
}

#[rstest]
#[case::missing_token_type(
	json!({
		"access_token": "upstream-token",
		"issued_token_type": TOKEN_TYPE_ACCESS,
		"expires_in": 3600,
	}),
	"missing token_type"
)]
#[case::empty_access_token(
	json!({
		"access_token": "",
		"token_type": "Bearer",
		"issued_token_type": TOKEN_TYPE_ACCESS,
		"expires_in": 3600,
	}),
	"empty access_token"
)]
#[tokio::test]
async fn rejects_invalid_token_response(
	#[case] response_body: serde_json::Value,
	#[case] expected: &str,
) {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(response_body)).await;
	let a = auth(endpoint(&mock));

	let err = fetch_token(
		&policy_client(),
		&a,
		exchange_req("subj", TOKEN_TYPE_ACCESS),
	)
	.await
	.unwrap_err();
	assert!(err.to_string().contains(expected), "got: {err}");
}

#[rstest]
#[case::issued_type_mismatch(
	OAuthGrantType::TokenExchange,
	Some(TOKEN_TYPE_JWT),
	TOKEN_TYPE_ACCESS,
	"expected"
)]
#[case::explicit_access_mismatch(
	OAuthGrantType::TokenExchange,
	Some(TOKEN_TYPE_ACCESS),
	TOKEN_TYPE_JWT,
	"expected"
)]
#[tokio::test]
async fn rejects_mismatched_issued_token_type(
	#[case] grant_type: OAuthGrantType,
	#[case] requested_token_type: Option<&str>,
	#[case] issued_token_type: &str,
	#[case] expected_err: &str,
) {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(json!({
		"access_token": "t",
		"token_type": "Bearer",
		"issued_token_type": issued_token_type,
	})))
	.await;
	let a = OAuthTokenExchangeAuth {
		grant_type,
		requested_token_type: requested_token_type.map(token_type_from_urn),
		..base_auth(endpoint(&mock))
	};

	let err = fetch_token(
		&policy_client(),
		&a,
		exchange_req("subj", TOKEN_TYPE_ACCESS),
	)
	.await
	.unwrap_err();
	assert!(err.to_string().contains(expected_err), "got: {err}");
}

#[tokio::test]
async fn unset_requested_token_type_accepts_any_issued_type() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(json!({
		"access_token": "t",
		"token_type": "Bearer",
		"issued_token_type": TOKEN_TYPE_JWT,
	})))
	.await;
	let a = OAuthTokenExchangeAuth {
		grant_type: OAuthGrantType::TokenExchange,
		requested_token_type: None,
		..base_auth(endpoint(&mock))
	};

	let token = fetch_token(
		&policy_client(),
		&a,
		exchange_req("subj", TOKEN_TYPE_ACCESS),
	)
	.await
	.expect("unset requested_token_type should not validate issued_token_type");
	assert_eq!(token.expose_secret(), "t");

	let pairs = sent_form_params(&mock).await;
	assert!(
		!pairs.contains_key("requested_token_type"),
		"requested_token_type must be omitted when unset"
	);
}

#[tokio::test]
async fn unset_requested_token_type_accepts_response_without_issued_token_type() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(json!({
		"access_token": "t",
		"token_type": "Bearer",
	})))
	.await;
	let a = OAuthTokenExchangeAuth {
		grant_type: OAuthGrantType::TokenExchange,
		requested_token_type: None,
		..base_auth(endpoint(&mock))
	};

	let token = fetch_token(
		&policy_client(),
		&a,
		exchange_req("subj", TOKEN_TYPE_ACCESS),
	)
	.await
	.expect("unset requested_token_type should accept a missing issued_token_type");
	assert_eq!(token.expose_secret(), "t");
}

#[tokio::test]
async fn jwt_bearer_ignores_unexpected_issued_token_type() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(json!({
		"access_token": "t",
		"token_type": "Bearer",
		"issued_token_type": "urn:ietf:params:oauth:token-type:saml2",
	})))
	.await;
	let a = OAuthTokenExchangeAuth {
		grant_type: OAuthGrantType::JwtBearer,
		..base_auth(endpoint(&mock))
	};

	let token = fetch_token(
		&policy_client(),
		&a,
		exchange_req("subj", TOKEN_TYPE_ACCESS),
	)
	.await
	.expect("jwt-bearer response should not validate unneeded issued_token_type");
	assert_eq!(token.expose_secret(), "t");
}

#[rstest]
#[case(400, true)]
#[case(401, false)]
#[case(403, false)]
#[case(503, false)]
#[tokio::test]
async fn maps_error_status_by_class(#[case] status: u16, #[case] expect_client_error: bool) {
	let response = ResponseTemplate::new(status)
		.set_body_string(r#"{"error":"invalid_grant","error_description":"provider diagnostic"}"#);
	let mock = mock_token_endpoint(response).await;
	let a = auth(endpoint(&mock));

	let err = fetch_token(
		&policy_client(),
		&a,
		exchange_req("subj", TOKEN_TYPE_ACCESS),
	)
	.await
	.unwrap_err();
	if expect_client_error {
		assert!(
			matches!(err, FetchError::Client { status: actual, .. } if actual == ::http::StatusCode::from_u16(status).unwrap()),
			"got: {err:?}"
		);
	} else {
		assert!(matches!(err, FetchError::Upstream(_)), "got: {err:?}");
		let msg = err.to_string();
		assert!(msg.contains(&format!("token exchange returned status {status}")));
		assert!(!msg.contains("invalid_grant"), "got: {msg}");
		assert!(!msg.contains("provider diagnostic"), "got: {msg}");
	}
}

#[tokio::test]
async fn appends_additional_params() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
	let a = auth(endpoint(&mock));
	let req = ExchangeRequest {
		subject_token: "subj".to_string().into(),
		subject_token_type: OAuthTokenType::AccessToken,
		actor: None,
		extra_params: vec![
			("vendor_id".into(), "v1".into()),
			("org".into(), "o2".into()),
		],
		chained_extra_params: vec![],
	};

	fetch_token(&policy_client(), &a, req).await.unwrap();

	let pairs = sent_form_params(&mock).await;
	assert_eq!(pairs["vendor_id"], "v1");
	assert_eq!(pairs["org"], "o2");
}

#[test]
fn evaluates_additional_params() {
	let (expr, err) = cel::Expression::new_permissive("\"static-value\"".to_string());
	assert!(err.is_none(), "{err:?}");
	let a = OAuthTokenExchangeAuth {
		additional_params: BTreeMap::from([("p".to_string(), Arc::new(expr))]),
		..base_auth(Arc::new(SimpleBackendReference::Invalid))
	};
	let req = ::http::Request::builder()
		.method(::http::Method::GET)
		.uri("http://example/")
		.body(Body::empty())
		.unwrap();

	let params = a.evaluate_additional_params(&req).unwrap();
	assert_eq!(params, vec![("p".to_string(), "static-value".to_string())]);
}

#[test]
fn rejects_reserved_additional_param() {
	let proto = proto::OAuthTokenExchange {
		additional_params: std::collections::HashMap::from([(
			"client_assertion".to_string(),
			"x".to_string(),
		)]),
		..Default::default()
	};
	let err = OAuthTokenExchangeAuth::from_proto(proto, &mut Diagnostics::default()).unwrap_err();
	assert!(
		matches!(err, ProtoError::Generic(ref m) if m.contains("reserved")),
		"got: {err:?}"
	);
}

#[test]
fn invalid_cel_additional_param_parses_permissively() {
	let proto = proto::OAuthTokenExchange {
		additional_params: HashMap::from([("p".to_string(), "((".to_string())]),
		..Default::default()
	};
	// Like the rest of the xDS path, a bad CEL expression is parsed permissively:
	// conversion succeeds and the expression fails when evaluated at request time
	// instead of rejecting the whole config push.
	let auth = OAuthTokenExchangeAuth::from_proto(proto, &mut Diagnostics::default()).unwrap();
	assert!(
		auth
			.evaluate_additional_params(&incoming_request())
			.is_err()
	);
}

fn assert_load_err(auth: OAuthTokenExchangeAuth, expected: &str) {
	let err = auth
		.validate_load()
		.expect_err("invalid local config should fail validation");
	assert!(
		err.contains(expected),
		"expected error containing {expected:?}, got {err:?}"
	);
}

#[rstest]
#[case::token_endpoint_path(
	OAuthTokenExchangeAuth {
		path: "token".into(),
		..base_auth(Arc::new(SimpleBackendReference::Invalid))
	},
	"must start with /"
)]
#[case::jwt_bearer_actor_token(
	OAuthTokenExchangeAuth {
		grant_type: OAuthGrantType::JwtBearer,
		actor_token: Some(ActorTokenSpec {
			source: Some(AuthorizationLocation::default()),
			token_request: None,
			token_requests: None,
			token_type: OAuthTokenType::default(),
			enforce_may_act: false,
		}),
		..base_auth(Arc::new(SimpleBackendReference::Invalid))
	},
	"actor_token"
)]
#[case::enforce_may_act_non_jwt_actor_token(
	OAuthTokenExchangeAuth {
		actor_token: Some(ActorTokenSpec {
			source: Some(AuthorizationLocation::Header {
				name: ::http::HeaderName::from_static("x-actor-token"),
				prefix: None,
			}),
			token_request: None,
			token_requests: None,
			token_type: OAuthTokenType::AccessToken,
			enforce_may_act: true,
		}),
		..base_auth(Arc::new(SimpleBackendReference::Invalid))
	},
	"requires actor_token.token_type"
)]
#[case::basic_without_secret(
	OAuthTokenExchangeAuth {
		client_auth: Some(OAuthClientAuth {
			client_id: "gateway-client".into(),
			method: OAuthClientAuthMethod::ClientSecretBasic {
				client_secret: "".into(),
			},
		}),
		..base_auth(Arc::new(SimpleBackendReference::Invalid))
	},
	"client_secret"
)]
#[case::empty_client_id(
	OAuthTokenExchangeAuth {
		client_auth: Some(OAuthClientAuth {
			client_id: String::new(),
			method: OAuthClientAuthMethod::ClientSecretPost {
				client_secret: Some("secret".into()),
			},
		}),
		..base_auth(Arc::new(SimpleBackendReference::Invalid))
	},
	"client_id"
)]
#[case::empty_client_secret(
	OAuthTokenExchangeAuth {
		client_auth: Some(OAuthClientAuth {
			client_id: "gateway-client".into(),
			method: OAuthClientAuthMethod::ClientSecretPost {
				client_secret: Some("".into()),
			},
		}),
		..base_auth(Arc::new(SimpleBackendReference::Invalid))
	},
	"client_secret"
)]
#[case::reserved_additional_param(
	OAuthTokenExchangeAuth {
		additional_params: BTreeMap::from([(
			"scope".into(),
			Arc::new(cel::Expression::new_strict(r#""read""#).unwrap()),
		)]),
		..base_auth(Arc::new(SimpleBackendReference::Invalid))
	},
	"reserved"
)]
#[case::plain_oauth_id_jag(
	OAuthTokenExchangeAuth {
		requested_token_type: Some(OAuthTokenType::IdJag),
		audiences: vec!["https://resource-as.example".into()],
		..base_auth(Arc::new(SimpleBackendReference::Invalid))
	},
	"backendAuth.crossAppAccess"
)]
#[case::expression_output_location(
	OAuthTokenExchangeAuth {
		authorization_location: AuthorizationLocation::Expression(Arc::new(cel::Expression::new_strict(r#""token""#).unwrap())),
		..base_auth(Arc::new(SimpleBackendReference::Invalid))
	},
	"credential extraction"
)]
#[test]
fn validate_load_rejects_invalid_local_config(
	#[case] auth: OAuthTokenExchangeAuth,
	#[case] expected: &str,
) {
	assert_load_err(auth, expected);
}

#[test]
fn accepts_supported_requested_token_types_from_proto() {
	for token_type in [TOKEN_TYPE_ACCESS, TOKEN_TYPE_JWT, TOKEN_TYPE_ID] {
		let auth = OAuthTokenExchangeAuth::from_proto(
			proto::OAuthTokenExchange {
				requested_token_type: Some(token_type.to_string()),
				..Default::default()
			},
			&mut Diagnostics::default(),
		)
		.unwrap();
		assert_eq!(
			auth.requested_token_type,
			Some(token_type_from_urn(token_type))
		);
	}
}

#[test]
fn private_key_jwt_client_auth_from_proto() {
	let auth = OAuthClientAuth::try_from(proto::OAuthClientAuth {
		client_id: "gateway-client".to_string(),
		method: proto::o_auth_client_auth::Method::PrivateKeyJwt as i32,
		private_key_jwt: Some(proto::o_auth_client_auth::PrivateKeyJwt {
			signing_key: TEST_EC_PRIVATE_KEY_PEM.to_string(),
			certificate: TEST_EC_CERT_PEM.to_string(),
			certificate_header: proto::o_auth_client_auth::private_key_jwt::CertificateHeader::X5c as i32,
			alg: proto::JwtSigningAlg::Es256 as i32,
			kid: Some("kid-1".to_string()),
			assertion_audience: "https://issuer.example/token".to_string(),
		}),
		..Default::default()
	})
	.unwrap();

	assert_eq!(auth.client_id, "gateway-client");
	match auth.method {
		OAuthClientAuthMethod::PrivateKeyJwt(private_key) => {
			let serialized = serde_json::to_value(private_key).unwrap();
			assert_eq!(serialized["alg"].as_str(), Some("ES256"));
			assert_eq!(serialized["kid"].as_str(), Some("kid-1"));
			assert_eq!(serialized["x5c"], json!([TEST_EC_CERT_DER_BASE64]));
			assert_eq!(
				serialized["assertionAudience"].as_str(),
				Some("https://issuer.example/token")
			);
		},
		other => panic!("expected privateKeyJwt client auth, got {other:?}"),
	}
}

#[test]
fn private_key_jwt_serialization_omits_unset_optional_headers() {
	let private_key = PrivateKeyJwt::try_from(RawPrivateKeyJwt {
		signing_key: Some(SecretString::from(TEST_EC_PRIVATE_KEY_PEM)),
		signer: None,
		certificate: None,
		certificate_header: None,
		alg: JwtSigningAlg::Es256,
		kid: None,
		assertion_audience: "https://issuer.example/token".into(),
	})
	.unwrap();

	let serialized = serde_json::to_value(private_key).unwrap();
	assert!(serialized.get("kid").is_none());
	assert!(serialized.get("x5c").is_none());
	assert!(serialized.get("x5t#S256").is_none());
}

#[rstest]
#[case::unsupported_requested_token_type(
	proto::OAuthTokenExchange {
		requested_token_type: Some("urn:ietf:params:oauth:token-type:saml2".to_string()),
		..Default::default()
	},
	"unsupported requested_token_type"
)]
#[case::id_jag_unsupported_over_xds(
	proto::OAuthTokenExchange {
		requested_token_type: Some(TOKEN_TYPE_ID_JAG.to_string()),
		..Default::default()
	},
	"only supported by local backendAuth.crossAppAccess"
)]
#[case::invalid_subject_token_type(
	proto::OAuthTokenExchange {
		subject_token: Some(proto::o_auth_token_exchange::TokenSpec {
			token_type: "not a uri".to_string(),
			..Default::default()
		}),
		..Default::default()
	},
	"unsupported subject_token.token_type"
)]
#[case::non_slash_token_endpoint_path(
	proto::OAuthTokenExchange {
		token_endpoint_path: Some("noslash".to_string()),
		..Default::default()
	},
	"must start with /"
)]
#[case::empty_client_id(
	proto::OAuthTokenExchange {
		client_auth: Some(proto::OAuthClientAuth {
			client_id: String::new(),
			client_secret: Some("s".to_string()),
			method: proto::o_auth_client_auth::Method::ClientSecretPost as i32,
			..Default::default()
		}),
		..Default::default()
	},
	"client_id"
)]
#[case::empty_client_secret(
	proto::OAuthTokenExchange {
		client_auth: Some(proto::OAuthClientAuth {
			client_id: "gateway-client".to_string(),
			client_secret: Some(String::new()),
			method: proto::o_auth_client_auth::Method::ClientSecretPost as i32,
			..Default::default()
		}),
		..Default::default()
	},
	"client_secret"
)]
#[case::private_key_jwt_missing_settings(
	proto::OAuthTokenExchange {
		client_auth: Some(proto::OAuthClientAuth {
			client_id: "gateway-client".to_string(),
			method: proto::o_auth_client_auth::Method::PrivateKeyJwt as i32,
			..Default::default()
		}),
		..Default::default()
	},
	"private_key_jwt settings are required"
)]
#[case::private_key_jwt_with_client_secret(
	proto::OAuthTokenExchange {
		client_auth: Some(proto::OAuthClientAuth {
			client_id: "gateway-client".to_string(),
			client_secret: Some("secret".to_string()),
			method: proto::o_auth_client_auth::Method::PrivateKeyJwt as i32,
			private_key_jwt: Some(proto::o_auth_client_auth::PrivateKeyJwt {
				signing_key: TEST_EC_PRIVATE_KEY_PEM.to_string(),
				alg: proto::JwtSigningAlg::Es256 as i32,
				assertion_audience: "https://issuer.example/token".to_string(),
				..Default::default()
			}),
		}),
		..Default::default()
	},
	"must not set client_secret"
)]
#[case::private_key_jwt_settings_with_secret_method(
	proto::OAuthTokenExchange {
		client_auth: Some(proto::OAuthClientAuth {
			client_id: "gateway-client".to_string(),
			client_secret: Some("secret".to_string()),
			method: proto::o_auth_client_auth::Method::ClientSecretPost as i32,
			private_key_jwt: Some(proto::o_auth_client_auth::PrivateKeyJwt {
				signing_key: TEST_EC_PRIVATE_KEY_PEM.to_string(),
				alg: proto::JwtSigningAlg::Es256 as i32,
				assertion_audience: "https://issuer.example/token".to_string(),
				..Default::default()
			}),
		}),
		..Default::default()
	},
	"requires the PRIVATE_KEY_JWT method"
)]
#[case::private_key_jwt_certificate_without_header(
	proto::OAuthTokenExchange {
		client_auth: Some(proto::OAuthClientAuth {
			client_id: "gateway-client".to_string(),
			method: proto::o_auth_client_auth::Method::PrivateKeyJwt as i32,
			private_key_jwt: Some(proto::o_auth_client_auth::PrivateKeyJwt {
				signing_key: TEST_EC_PRIVATE_KEY_PEM.to_string(),
				certificate: TEST_EC_CERT_PEM.to_string(),
				alg: proto::JwtSigningAlg::Es256 as i32,
				assertion_audience: "https://issuer.example/token".to_string(),
				..Default::default()
			}),
			..Default::default()
		}),
		..Default::default()
	},
	"certificate_header is required when certificate is set"
)]
#[case::jwt_bearer_actor_token(
	proto::OAuthTokenExchange {
		grant_type: proto::o_auth_token_exchange::GrantType::JwtBearer as i32,
		actor_token: Some(proto::o_auth_token_exchange::ActorToken::default()),
		..Default::default()
	},
	"actor_token"
)]
#[case::actor_token_without_source(
	proto::OAuthTokenExchange {
		actor_token: Some(proto::o_auth_token_exchange::ActorToken::default()),
		..Default::default()
	},
	"actor_token.source"
)]
#[case::enforce_may_act_non_jwt_actor_token(
	proto::OAuthTokenExchange {
		actor_token: Some(proto::o_auth_token_exchange::ActorToken {
			source: Some(proto::AuthorizationLocation {
				kind: Some(proto::authorization_location::Kind::Header(
					proto::authorization_location::Header {
						name: "x-actor-token".to_string(),
						prefix: None,
					},
				)),
			}),
			token_type: TOKEN_TYPE_ACCESS.to_string(),
			enforce_may_act: true,
		}),
		..Default::default()
	},
	"requires actor_token.token_type"
)]
#[case::expression_output_location(
	proto::OAuthTokenExchange {
		authorization_location: Some(proto::AuthorizationLocation {
			kind: Some(proto::authorization_location::Kind::Expression(
				"foo".to_string(),
			)),
		}),
		..Default::default()
	},
	"credential extraction"
)]
#[test]
fn rejects_invalid_proto_config(#[case] proto: proto::OAuthTokenExchange, #[case] expected: &str) {
	assert_proto_err_contains(proto, expected);
}

#[test]
fn disabled_cache_from_proto_disables_storage() {
	let cfg = token_cache_config_from_proto(Some(proto::o_auth_token_exchange::TokenCache {
		in_memory: Some(proto::o_auth_token_exchange::token_cache::InMemory {
			max_entries: Some(0),
			default_ttl: None,
		}),
	}))
	.unwrap();

	assert!(cfg.into_cache().is_none());

	let auth = OAuthTokenExchangeAuth::from_proto(
		proto::OAuthTokenExchange {
			cache: Some(proto::o_auth_token_exchange::TokenCache {
				in_memory: Some(proto::o_auth_token_exchange::token_cache::InMemory {
					max_entries: Some(0),
					default_ttl: None,
				}),
			}),
			..Default::default()
		},
		&mut Diagnostics::default(),
	)
	.unwrap();

	assert!(auth.cache.is_none());
}

#[test]
fn cache_from_proto_defaults_to_in_memory_cache() {
	let cfg = token_cache_config_from_proto(None).unwrap();

	assert_eq!(cfg.max_entries, None);
	assert_eq!(cfg.default_ttl, None);
}

#[test]
fn in_memory_cache_from_proto_uses_default_ttl_and_capacity_defaults() {
	let cfg = token_cache_config_from_proto(Some(proto::o_auth_token_exchange::TokenCache {
		in_memory: Some(proto::o_auth_token_exchange::token_cache::InMemory {
			max_entries: None,
			default_ttl: Some(prost_types::Duration {
				seconds: 42,
				nanos: 0,
			}),
		}),
	}))
	.unwrap();

	assert_eq!(cfg.max_entries, None);
	assert_eq!(cfg.default_ttl, Some(Duration::from_secs(42)));
}

#[test]
fn in_memory_cache_from_proto_uses_default_ttl_for_negative_default_ttl() {
	let cfg = token_cache_config_from_proto(Some(proto::o_auth_token_exchange::TokenCache {
		in_memory: Some(proto::o_auth_token_exchange::token_cache::InMemory {
			max_entries: None,
			default_ttl: Some(prost_types::Duration {
				seconds: -1,
				nanos: 0,
			}),
		}),
	}))
	.unwrap();

	assert_eq!(cfg.default_ttl, None);
}

#[test]
fn in_memory_cache_from_proto_accepts_large_default_ttl() {
	let cfg = token_cache_config_from_proto(Some(proto::o_auth_token_exchange::TokenCache {
		in_memory: Some(proto::o_auth_token_exchange::token_cache::InMemory {
			max_entries: None,
			default_ttl: Some(prost_types::Duration {
				seconds: i64::MAX,
				nanos: 999_999_999,
			}),
		}),
	}))
	.unwrap();

	assert_eq!(
		cfg.default_ttl,
		Some(Duration::from_secs(i64::MAX as u64) + Duration::from_nanos(999_999_999))
	);
}

#[rstest]
#[case(TOKEN_TYPE_ACCESS, true)]
#[case(TOKEN_TYPE_JWT, true)]
#[case(TOKEN_TYPE_ID, true)]
#[case("urn:ietf:params:oauth:token-type:saml2", true)]
#[case("urn:company:domain:human", true)]
#[case("not a uri", false)]
#[case("https://tokens.example/custom#fragment", false)]
fn oauth_token_type_from_urn_cases(#[case] token_type: &str, #[case] expected: bool) {
	assert_eq!(OAuthTokenType::from_urn(token_type).is_some(), expected);
}

#[tokio::test]
async fn sends_actor_token() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
	let a = auth(endpoint(&mock));
	let req = ExchangeRequest {
		subject_token: "subj".to_string().into(),
		subject_token_type: OAuthTokenType::AccessToken,
		actor: Some(("actor-tok".to_string().into(), OAuthTokenType::Jwt)),
		extra_params: vec![],
		chained_extra_params: vec![],
	};

	fetch_token(&policy_client(), &a, req).await.unwrap();

	let pairs = sent_form_params(&mock).await;
	assert_eq!(pairs["actor_token"], "actor-tok");
	assert_eq!(pairs["actor_token_type"], TOKEN_TYPE_JWT);
}

fn actor_token_with_header(enforce_may_act: bool) -> ActorTokenSpec {
	ActorTokenSpec {
		source: Some(AuthorizationLocation::Header {
			name: ::http::HeaderName::from_static("x-actor-token"),
			prefix: None,
		}),
		token_request: None,
		token_requests: None,
		token_type: OAuthTokenType::Jwt,
		enforce_may_act,
	}
}

#[test]
fn actor_token_does_not_fallback_to_subject_claims() {
	let subject = "subject-token";
	let mut req = incoming_request();
	req
		.extensions_mut()
		.insert(claims_with_may_act(subject, json!({"sub": "actor-a"})));

	let spec = actor_token_with_header(false);
	let err =
		actor_token_from_request(&spec, spec.source.as_ref().unwrap(), &req, subject).unwrap_err();
	assert!(matches!(err, ProxyError::InvalidRequest));
}

fn request_with_actor_header(subject: &str, actor: &str) -> crate::http::Request {
	::http::Request::builder()
		.method(::http::Method::GET)
		.uri("http://upstream/")
		.header(::http::header::AUTHORIZATION, format!("Bearer {subject}"))
		.header("x-actor-token", actor)
		.body(Body::empty())
		.unwrap()
}

fn backend_auth_requiring_may_act(mock: &MockServer) -> crate::http::auth::BackendAuth {
	let a = OAuthTokenExchangeAuth {
		actor_token: Some(actor_token_with_header(true)),
		..auth(endpoint(mock))
	};
	crate::http::auth::BackendAuth::new(crate::http::auth::BackendAuthKind::OAuthTokenExchange(
		Box::new(a),
	))
}

#[test]
fn actor_token_authorization_from_proto() {
	let proto = proto::OAuthTokenExchange {
		actor_token: Some(proto::o_auth_token_exchange::ActorToken {
			source: Some(proto::AuthorizationLocation {
				kind: Some(proto::authorization_location::Kind::Header(
					proto::authorization_location::Header {
						name: "x-actor-token".to_string(),
						prefix: None,
					},
				)),
			}),
			enforce_may_act: true,
			token_type: TOKEN_TYPE_JWT.to_string(),
		}),
		..Default::default()
	};
	let auth = OAuthTokenExchangeAuth::from_proto(proto, &mut Diagnostics::default()).unwrap();
	assert!(auth.actor_token.unwrap().enforce_may_act);
}

#[rstest]
#[case::exact_match(json!({"sub": "actor-a"}), "actor-a", true)]
#[case::actor_in_allowed_list(json!({"sub": ["actor-a", "actor-b"]}), "actor-b", true)]
#[case::actor_not_allowed(json!({"sub": "actor-a"}), "actor-b", false)]
#[case::non_object_may_act_claim(json!("actor-a"), "actor-a", false)]
#[tokio::test]
async fn enforce_may_act_checks_validated_subject_claims(
	#[case] may_act: serde_json::Value,
	#[case] actor_sub: &str,
	#[case] expect_authorized: bool,
) {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
	let backend_auth = backend_auth_requiring_may_act(&mock);

	let subject = jwt_with_claims(&json!({"sub": "subject-a"}));
	let actor = jwt_with_claims(&json!({"sub": actor_sub}));
	let mut req = request_with_actor_header(&subject, &actor);
	req
		.extensions_mut()
		.insert(claims_with_may_act(&subject, may_act));

	let result =
		crate::http::auth::apply_backend_auth(&backend_info(), &backend_auth, &mut req).await;
	if expect_authorized {
		result.unwrap();
	} else {
		assert!(matches!(
			result.unwrap_err(),
			ProxyError::AuthorizationFailed
		));
		assert!(mock.received_requests().await.unwrap().is_empty());
	}
}

#[tokio::test]
async fn enforce_may_act_ignores_validated_claims_for_a_different_subject_token() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
	let backend_auth = backend_auth_requiring_may_act(&mock);

	let subject = jwt_with_claims(&json!({"may_act": {"sub": "actor-a"}}));
	let actor = jwt_with_claims(&json!({"sub": "actor-b"}));
	let mut req = request_with_actor_header(&subject, &actor);
	req.extensions_mut().insert(claims_with_may_act(
		"some-other-subject",
		json!({"sub": "actor-b"}),
	));

	let err = crate::http::auth::apply_backend_auth(&backend_info(), &backend_auth, &mut req)
		.await
		.unwrap_err();
	assert!(matches!(err, ProxyError::AuthorizationFailed));
	assert!(mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn enforce_may_act_falls_back_to_unvalidated_subject_token_without_jwt_policy() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
	let backend_auth = backend_auth_requiring_may_act(&mock);

	let subject = jwt_with_claims(&json!({"may_act": {"sub": "actor-a"}}));
	let mut req = request_with_actor_header(&subject, &jwt_with_claims(&json!({"sub": "actor-a"})));

	crate::http::auth::apply_backend_auth(&backend_info(), &backend_auth, &mut req)
		.await
		.unwrap();
}

#[tokio::test]
async fn rejects_na_token_type_as_non_bearer() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(json!({
		"access_token": "delegated-token",
		"token_type": "N_A",
		"issued_token_type": TOKEN_TYPE_ACCESS,
	})))
	.await;
	let a = auth(endpoint(&mock));

	let err = fetch_token(
		&policy_client(),
		&a,
		exchange_req("subj", TOKEN_TYPE_ACCESS),
	)
	.await
	.unwrap_err();
	assert!(err.to_string().contains("unsupported token_type: N_A"));
}

#[test]
fn subject_token_source_and_type_from_proto() {
	let proto = proto::OAuthTokenExchange {
		subject_token: Some(proto::o_auth_token_exchange::TokenSpec {
			source: Some(proto::AuthorizationLocation {
				kind: Some(proto::authorization_location::Kind::Header(
					proto::authorization_location::Header {
						name: "x-subject".to_string(),
						prefix: None,
					},
				)),
			}),
			token_type: String::new(),
		}),
		..Default::default()
	};
	let auth = OAuthTokenExchangeAuth::from_proto(proto, &mut Diagnostics::default()).unwrap();
	assert!(
		matches!(&auth.subject_token.source, AuthorizationLocation::Header { name, .. } if name.as_str() == "x-subject")
	);
	// Empty proto token_type defaults to access_token.
	assert_eq!(auth.subject_token.token_type, OAuthTokenType::AccessToken);
}

#[test]
fn authorization_location_from_proto() {
	let proto = proto::OAuthTokenExchange {
		authorization_location: Some(proto::AuthorizationLocation {
			kind: Some(proto::authorization_location::Kind::Header(
				proto::authorization_location::Header {
					name: "x-upstream-auth".to_string(),
					prefix: None,
				},
			)),
		}),
		..Default::default()
	};
	let auth = OAuthTokenExchangeAuth::from_proto(proto, &mut Diagnostics::default()).unwrap();
	assert!(matches!(
		auth.authorization_location,
		AuthorizationLocation::Header { ref name, .. } if name.as_str() == "x-upstream-auth"
	));
}

#[test]
fn query_parameter_authorization_location_from_proto() {
	let proto = proto::OAuthTokenExchange {
		authorization_location: Some(proto::AuthorizationLocation {
			kind: Some(proto::authorization_location::Kind::QueryParameter(
				proto::authorization_location::QueryParameter {
					name: "access_token".to_string(),
				},
			)),
		}),
		..Default::default()
	};
	let auth = OAuthTokenExchangeAuth::from_proto(proto, &mut Diagnostics::default()).unwrap();
	assert!(matches!(
		auth.authorization_location,
		AuthorizationLocation::QueryParameter { ref name } if name.as_str() == "access_token"
	));
}

#[tokio::test]
async fn dispatch_inserts_default_bearer_and_marks_explicit() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
	let backend_auth = crate::http::auth::BackendAuth::new(
		crate::http::auth::BackendAuthKind::OAuthTokenExchange(Box::new(auth(endpoint(&mock)))),
	);
	let mut req = incoming_request();

	crate::http::auth::apply_backend_auth(&backend_info(), &backend_auth, &mut req)
		.await
		.unwrap();

	let hv = req
		.headers()
		.get(::http::header::AUTHORIZATION)
		.unwrap()
		.to_str()
		.unwrap();
	assert_eq!(hv, "Bearer upstream-token");
	let applied = req
		.extensions()
		.get::<crate::http::auth::AppliedBackendAuthLocation>()
		.unwrap();
	assert!(applied.explicit, "oauth output must be marked explicit");
}

#[tokio::test]
async fn dispatch_uses_configured_output_location_and_marks_explicit() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
	let a = OAuthTokenExchangeAuth {
		authorization_location: AuthorizationLocation::Header {
			name: ::http::HeaderName::from_static("x-upstream-auth"),
			prefix: None,
		},
		..auth(endpoint(&mock))
	};
	let backend_auth = crate::http::auth::BackendAuth::new(
		crate::http::auth::BackendAuthKind::OAuthTokenExchange(Box::new(a)),
	);
	let mut req = incoming_request();

	crate::http::auth::apply_backend_auth(&backend_info(), &backend_auth, &mut req)
		.await
		.unwrap();

	let hv = req
		.headers()
		.get("x-upstream-auth")
		.unwrap()
		.to_str()
		.unwrap();
	assert_eq!(hv, "upstream-token");
	let applied = req
		.extensions()
		.get::<crate::http::auth::AppliedBackendAuthLocation>()
		.unwrap();
	assert!(
		applied.explicit,
		"configured location must be marked explicit"
	);
}

#[tokio::test]
async fn dispatch_supports_query_parameter_output_location() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
	let a = OAuthTokenExchangeAuth {
		authorization_location: AuthorizationLocation::QueryParameter {
			name: "access_token".into(),
		},
		..auth(endpoint(&mock))
	};
	let backend_auth = crate::http::auth::BackendAuth::new(
		crate::http::auth::BackendAuthKind::OAuthTokenExchange(Box::new(a)),
	);
	let mut req = incoming_request();

	crate::http::auth::apply_backend_auth(&backend_info(), &backend_auth, &mut req)
		.await
		.unwrap();

	assert!(req.headers().get(::http::header::AUTHORIZATION).is_none());
	assert_eq!(req.uri().query(), Some("access_token=upstream-token"));
	let applied = req
		.extensions()
		.get::<crate::http::auth::AppliedBackendAuthLocation>()
		.unwrap();
	assert!(applied.explicit, "query output must be marked explicit");
}

#[tokio::test]
async fn dispatch_removes_input_token_locations_before_inserting_output() {
	let mock = mock_token_endpoint(ResponseTemplate::new(200).set_body_json(token_body())).await;
	let a = OAuthTokenExchangeAuth {
		actor_token: Some(ActorTokenSpec {
			source: Some(AuthorizationLocation::Header {
				name: ::http::HeaderName::from_static("x-actor-token"),
				prefix: None,
			}),
			token_request: None,
			token_requests: None,
			token_type: OAuthTokenType::Jwt,
			enforce_may_act: false,
		}),
		authorization_location: AuthorizationLocation::Header {
			name: ::http::HeaderName::from_static("x-upstream-auth"),
			prefix: None,
		},
		..auth(endpoint(&mock))
	};
	let backend_auth = crate::http::auth::BackendAuth::new(
		crate::http::auth::BackendAuthKind::OAuthTokenExchange(Box::new(a)),
	);
	let mut req = ::http::Request::builder()
		.method(::http::Method::GET)
		.uri("http://upstream/")
		.header(::http::header::AUTHORIZATION, "Bearer subj")
		.header("x-actor-token", "actor")
		.body(Body::empty())
		.unwrap();

	crate::http::auth::apply_backend_auth(&backend_info(), &backend_auth, &mut req)
		.await
		.unwrap();

	assert!(req.headers().get(::http::header::AUTHORIZATION).is_none());
	assert!(req.headers().get("x-actor-token").is_none());
	assert_eq!(
		req
			.headers()
			.get("x-upstream-auth")
			.unwrap()
			.to_str()
			.unwrap(),
		"upstream-token"
	);
}

// ----- actor token the gateway obtains itself (actorToken.tokenRequest) -----

const GATEWAY_ACTOR_TOKEN: &str = "gateway-actor-token";

fn gateway_private_key_jwt() -> PrivateKeyJwt {
	PrivateKeyJwt::try_from(RawPrivateKeyJwt {
		signing_key: Some(SecretString::from(TEST_EC_PRIVATE_KEY_PEM)),
		signer: None,
		certificate: None,
		certificate_header: None,
		alg: JwtSigningAlg::Es256,
		kid: Some("gateway-key".into()),
		assertion_audience: "https://issuer.example".into(),
	})
	.unwrap()
}

fn actor_token_request(
	endpoint: Arc<SimpleBackendReference>,
	grant_type: ActorTokenGrant,
	client_auth: OAuthClientAuth,
) -> ActorTokenRequest {
	ActorTokenRequest {
		target: SimpleBackendReferenceWithPolicies {
			target: endpoint,
			policies: vec![],
		},
		path: "/actor".into(),
		grant_type,
		client_auth,
		audiences: vec![],
		scopes: vec!["openid".into()],
		resources: vec![],
		cache: actor_token_cache(),
	}
}

fn jwt_bearer_actor(endpoint: Arc<SimpleBackendReference>) -> ActorTokenRequest {
	actor_token_request(
		endpoint,
		ActorTokenGrant::JwtBearer,
		OAuthClientAuth {
			client_id: "gateway-user".into(),
			method: OAuthClientAuthMethod::PrivateKeyJwt(gateway_private_key_jwt()),
		},
	)
}

fn gateway_actor(token_request: ActorTokenRequest, token_type: OAuthTokenType) -> ActorTokenSpec {
	ActorTokenSpec {
		source: None,
		token_request: Some(token_request),
		token_requests: None,
		token_type,
		enforce_may_act: false,
	}
}

fn actor_token_body(access_token: &str, expires_in: u64) -> serde_json::Value {
	json!({"access_token": access_token, "token_type": "Bearer", "expires_in": expires_in})
}

/// One server, two endpoints: `/actor` (the gateway's own token) and `/token`
/// (the exchange). The expected call counts are verified when the server drops.
async fn mock_actor_and_exchange(
	actor: ResponseTemplate,
	actor_calls: u64,
	exchange_calls: u64,
) -> MockServer {
	let mock = MockServer::start().await;
	Mock::given(method("POST"))
		.and(path("/actor"))
		.respond_with(actor)
		.expect(actor_calls)
		.mount(&mock)
		.await;
	Mock::given(method("POST"))
		.and(path("/token"))
		.respond_with(ResponseTemplate::new(200).set_body_json(token_body()))
		.expect(exchange_calls)
		.mount(&mock)
		.await;
	mock
}

async fn forms_sent_to(mock: &MockServer, to: &str) -> Vec<HashMap<String, String>> {
	mock
		.received_requests()
		.await
		.unwrap()
		.iter()
		.filter(|r| r.url.path() == to)
		.map(|r| form_urlencoded::parse(&r.body).into_owned().collect())
		.collect()
}

fn backend_auth(a: OAuthTokenExchangeAuth) -> crate::http::auth::BackendAuth {
	crate::http::auth::BackendAuth::new(crate::http::auth::BackendAuthKind::OAuthTokenExchange(
		Box::new(a),
	))
}

fn request_with_subject(subject: &str) -> crate::http::Request {
	::http::Request::builder()
		.method(::http::Method::GET)
		.uri("http://upstream/")
		.header(::http::header::AUTHORIZATION, format!("Bearer {subject}"))
		.body(Body::empty())
		.unwrap()
}

#[tokio::test]
async fn gateway_actor_token_jwt_bearer_is_signed_by_the_gateway_and_sent_as_actor() {
	let mock = mock_actor_and_exchange(
		ResponseTemplate::new(200).set_body_json(actor_token_body(GATEWAY_ACTOR_TOKEN, 3600)),
		1,
		1,
	)
	.await;
	let a = OAuthTokenExchangeAuth {
		actor_token: Some(gateway_actor(
			jwt_bearer_actor(endpoint(&mock)),
			OAuthTokenType::AccessToken,
		)),
		..auth(endpoint(&mock))
	};
	let mut req = request_with_subject("subj");

	crate::http::auth::apply_backend_auth(&backend_info(), &backend_auth(a), &mut req)
		.await
		.unwrap();

	// The gateway's own token request: RFC 7523 with an assertion it signed.
	let actor = &forms_sent_to(&mock, "/actor").await[0];
	assert_eq!(actor["grant_type"], GRANT_TYPE_JWT_BEARER);
	assert_eq!(actor["scope"], "openid");
	assert!(!actor.contains_key("client_assertion"));
	assert!(!actor.contains_key("subject_token"));
	#[derive(serde::Deserialize)]
	struct AssertionClaims {
		iss: String,
		sub: String,
		aud: String,
	}
	let claims: AssertionClaims = decode_unverified_jwt_claims(&actor["assertion"]).unwrap();
	assert_eq!(claims.iss, "gateway-user");
	assert_eq!(claims.sub, "gateway-user");
	assert_eq!(claims.aud, "https://issuer.example");
	let header = jsonwebtoken::decode_header(&actor["assertion"]).unwrap();
	assert_eq!(header.kid.as_deref(), Some("gateway-key"));

	// The exchange: the caller's token as subject, the gateway's as actor.
	let exchange = &forms_sent_to(&mock, "/token").await[0];
	assert_eq!(exchange["grant_type"], GRANT_TYPE_TOKEN_EXCHANGE);
	assert_eq!(exchange["subject_token"], "subj");
	assert_eq!(exchange["actor_token"], GATEWAY_ACTOR_TOKEN);
	assert_eq!(exchange["actor_token_type"], TOKEN_TYPE_ACCESS);
	assert_eq!(
		req.headers().get(::http::header::AUTHORIZATION).unwrap(),
		"Bearer upstream-token"
	);
}

#[tokio::test]
async fn gateway_actor_token_client_credentials_authenticates_the_gateway() {
	let mock = mock_actor_and_exchange(
		ResponseTemplate::new(200).set_body_json(actor_token_body(GATEWAY_ACTOR_TOKEN, 3600)),
		1,
		1,
	)
	.await;
	let token_request = actor_token_request(
		endpoint(&mock),
		ActorTokenGrant::ClientCredentials,
		OAuthClientAuth {
			client_id: "gateway-client".into(),
			method: OAuthClientAuthMethod::ClientSecretBasic {
				client_secret: "gateway-secret".to_string().into(),
			},
		},
	);
	let a = OAuthTokenExchangeAuth {
		actor_token: Some(gateway_actor(token_request, OAuthTokenType::AccessToken)),
		..auth(endpoint(&mock))
	};

	crate::http::auth::apply_backend_auth(
		&backend_info(),
		&backend_auth(a),
		&mut request_with_subject("subj"),
	)
	.await
	.unwrap();

	let received = mock.received_requests().await.unwrap();
	let actor_req = received.iter().find(|r| r.url.path() == "/actor").unwrap();
	assert_eq!(
		actor_req.headers.get("authorization").unwrap(),
		&format!(
			"Basic {}",
			BASE64_STANDARD.encode("gateway-client:gateway-secret")
		)
	);
	let actor = &forms_sent_to(&mock, "/actor").await[0];
	assert_eq!(actor["grant_type"], "client_credentials");
	assert!(!actor.contains_key("assertion"));
	assert_eq!(
		forms_sent_to(&mock, "/token").await[0]["actor_token"],
		GATEWAY_ACTOR_TOKEN
	);
}

#[rstest]
// A fresh token serves every request until shortly before it expires.
#[case::cached_while_fresh(3600, 1)]
// A token inside the refresh margin is never reused: each request obtains a new one.
#[case::refreshed_near_expiry(1, 2)]
#[tokio::test]
async fn gateway_actor_token_is_cached_and_refreshed(
	#[case] expires_in: u64,
	#[case] expected_actor_calls: u64,
) {
	let mock = mock_actor_and_exchange(
		ResponseTemplate::new(200).set_body_json(actor_token_body(GATEWAY_ACTOR_TOKEN, expires_in)),
		expected_actor_calls,
		2,
	)
	.await;
	let auth = backend_auth(OAuthTokenExchangeAuth {
		actor_token: Some(gateway_actor(
			jwt_bearer_actor(endpoint(&mock)),
			OAuthTokenType::AccessToken,
		)),
		..auth(endpoint(&mock))
	});

	// Two callers, so the exchange itself is not a cache hit.
	for subject in ["subj-a", "subj-b"] {
		crate::http::auth::apply_backend_auth(
			&backend_info(),
			&auth,
			&mut request_with_subject(subject),
		)
		.await
		.unwrap();
	}
	for exchange in forms_sent_to(&mock, "/token").await {
		assert_eq!(exchange["actor_token"], GATEWAY_ACTOR_TOKEN);
	}
}

#[rstest]
#[case::server_error(ResponseTemplate::new(500))]
#[case::rejected(ResponseTemplate::new(401).set_body_json(json!({"error": "invalid_client"})))]
#[case::invalid_grant(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"})))]
#[case::not_bearer(ResponseTemplate::new(200).set_body_json(json!({"access_token": "x", "token_type": "N_A"})))]
#[tokio::test]
async fn gateway_actor_token_failure_fails_closed(#[case] actor_response: ResponseTemplate) {
	// No exchange is attempted without the actor, and the caller's token is not forwarded.
	let mock = mock_actor_and_exchange(actor_response, 1, 0).await;
	let a = OAuthTokenExchangeAuth {
		actor_token: Some(gateway_actor(
			jwt_bearer_actor(endpoint(&mock)),
			OAuthTokenType::AccessToken,
		)),
		..auth(endpoint(&mock))
	};
	let mut req = request_with_subject("subj");

	let result =
		crate::http::auth::apply_backend_auth(&backend_info(), &backend_auth(a), &mut req).await;

	assert!(result.is_err());
	assert!(forms_sent_to(&mock, "/token").await.is_empty());
}

#[rstest]
#[case::authorized("gateway-user", true)]
#[case::not_authorized("someone-else", false)]
#[tokio::test]
async fn gateway_actor_token_honors_enforce_may_act(
	#[case] may_act_sub: &str,
	#[case] expect_authorized: bool,
) {
	let actor_jwt = jwt_with_claims(&json!({"sub": "gateway-user"}));
	let mock = mock_actor_and_exchange(
		ResponseTemplate::new(200).set_body_json(actor_token_body(&actor_jwt, 3600)),
		1,
		u64::from(expect_authorized),
	)
	.await;
	let mut actor = gateway_actor(jwt_bearer_actor(endpoint(&mock)), OAuthTokenType::Jwt);
	actor.enforce_may_act = true;
	let a = OAuthTokenExchangeAuth {
		actor_token: Some(actor),
		..auth(endpoint(&mock))
	};
	let subject = jwt_with_claims(&json!({"sub": "subject-a"}));
	let mut req = request_with_subject(&subject);
	req
		.extensions_mut()
		.insert(claims_with_may_act(&subject, json!({"sub": may_act_sub})));

	let result =
		crate::http::auth::apply_backend_auth(&backend_info(), &backend_auth(a), &mut req).await;

	if expect_authorized {
		result.unwrap();
		assert_eq!(
			forms_sent_to(&mock, "/token").await[0]["actor_token"],
			actor_jwt
		);
	} else {
		assert!(matches!(
			result.unwrap_err(),
			ProxyError::AuthorizationFailed
		));
	}
}

#[tokio::test]
async fn gateway_actor_token_and_key_never_appear_in_debug_output() {
	let mock = mock_actor_and_exchange(
		ResponseTemplate::new(200).set_body_json(actor_token_body(GATEWAY_ACTOR_TOKEN, 3600)),
		1,
		1,
	)
	.await;
	let a = OAuthTokenExchangeAuth {
		actor_token: Some(gateway_actor(
			jwt_bearer_actor(endpoint(&mock)),
			OAuthTokenType::AccessToken,
		)),
		..auth(endpoint(&mock))
	};
	let auth = backend_auth(a.clone());
	crate::http::auth::apply_backend_auth(&backend_info(), &auth, &mut request_with_subject("subj"))
		.await
		.unwrap();

	// After a fetch the token sits in the cache; neither it nor the key may print.
	for debug in [format!("{a:?}"), format!("{auth:?}")] {
		assert!(!debug.contains(GATEWAY_ACTOR_TOKEN), "{debug}");
		assert!(!debug.contains("PRIVATE KEY"), "{debug}");
		assert!(!debug.contains("MIGHAgEAMBMGByqGSM49"), "{debug}");
	}
}

#[rstest]
#[case::both_sources(
	|t: ActorTokenRequest| ActorTokenSpec {
		source: Some(AuthorizationLocation::default()),
		..gateway_actor(t, OAuthTokenType::AccessToken)
	},
	"exactly one of source, tokenRequest or tokenRequests"
)]
#[case::no_source(
	|_t: ActorTokenRequest| ActorTokenSpec {
		source: None,
		token_request: None,
		token_requests: None,
		token_type: OAuthTokenType::AccessToken,
		enforce_may_act: false,
	},
	"one of source, tokenRequest or tokenRequests must be set"
)]
#[case::jwt_bearer_without_private_key(
	|t: ActorTokenRequest| gateway_actor(
		ActorTokenRequest {
			client_auth: OAuthClientAuth {
				client_id: "gateway-client".into(),
				method: OAuthClientAuthMethod::ClientSecretBasic {
					client_secret: "s".to_string().into(),
				},
			},
			..t
		},
		OAuthTokenType::AccessToken,
	),
	"requires clientAuth method privateKeyJwt"
)]
#[case::relative_path(
	|t: ActorTokenRequest| gateway_actor(
		ActorTokenRequest { path: "actor".into(), ..t },
		OAuthTokenType::AccessToken,
	),
	"must start with /"
)]
fn gateway_actor_token_validate_load(
	#[case] build: fn(ActorTokenRequest) -> ActorTokenSpec,
	#[case] expected: &str,
) {
	let spec = build(jwt_bearer_actor(Arc::new(SimpleBackendReference::Invalid)));
	let err = spec.validate_load().unwrap_err();
	assert!(err.contains(expected), "got: {err}");
}

#[test]
fn gateway_actor_token_deserializes_from_local_config() {
	let a: OAuthTokenExchangeAuth = serde_json::from_value(json!({
		"host": "issuer.example:443",
		"path": "/oauth/v2/token",
		"requestedTokenType": TOKEN_TYPE_JWT,
		"actorToken": {
			"tokenRequest": {
				"host": "issuer.example:443",
				"path": "/oauth/v2/token",
				"grantType": "jwtBearer",
				"clientAuth": {
					"method": "privateKeyJwt",
					"clientId": "gateway-user",
					"signingKey": TEST_EC_PRIVATE_KEY_PEM,
					"alg": "ES256",
					"kid": "gateway-key",
					"assertionAudience": "https://issuer.example",
				},
				"scopes": ["openid"],
			},
		},
	}))
	.unwrap();
	a.validate_load().unwrap();
	let actor = a.actor_token.unwrap();
	assert!(actor.source.is_none());
	let token_request = actor.token_request.unwrap();
	assert_eq!(token_request.grant_type, ActorTokenGrant::JwtBearer);
	assert_eq!(token_request.path, "/oauth/v2/token");
	assert_eq!(token_request.client_auth.client_id, "gateway-user");
}

// ----- one actor per key (actorToken.tokenRequests) -----

const ORG_CLAIM: &str = "urn:zitadel:iam:user:resourceowner:id";

fn org_actor(
	endpoint: Arc<SimpleBackendReference>,
	path: &str,
	client_id: &str,
) -> ActorTokenRequest {
	ActorTokenRequest {
		path: path.into(),
		client_auth: OAuthClientAuth {
			client_id: client_id.into(),
			method: OAuthClientAuthMethod::PrivateKeyJwt(gateway_private_key_jwt()),
		},
		..jwt_bearer_actor(endpoint)
	}
}

fn actor_per_org(endpoint: Arc<SimpleBackendReference>) -> ActorTokenSpec {
	ActorTokenSpec {
		source: None,
		token_request: None,
		token_requests: Some(KeyedActorTokenRequests {
			key: Arc::new(cel::Expression::new_strict(format!(r#"jwt["{ORG_CLAIM}"]"#)).unwrap()),
			requests: BTreeMap::from([
				(
					"org-a".to_string(),
					org_actor(endpoint.clone(), "/actor-a", "actor-a"),
				),
				(
					"org-b".to_string(),
					org_actor(endpoint, "/actor-b", "actor-b"),
				),
			]),
		}),
		token_type: OAuthTokenType::AccessToken,
		enforce_may_act: false,
	}
}

/// A caller whose verified JWT carries `claims` (as jwtAuth leaves them).
fn caller(subject: &str, claims: serde_json::Value) -> crate::http::Request {
	let serde_json::Value::Object(inner) = claims else {
		unreachable!()
	};
	let mut req = request_with_subject(subject);
	req.extensions_mut().insert(crate::http::jwt::Claims {
		inner,
		jwt: subject.to_string().into(),
	});
	req
}

async fn mock_two_actors(actor_a: u64, actor_b: u64, exchanges: u64) -> MockServer {
	let mock = MockServer::start().await;
	for (p, token, calls) in [
		("/actor-a", "actor-token-org-a", actor_a),
		("/actor-b", "actor-token-org-b", actor_b),
	] {
		Mock::given(method("POST"))
			.and(path(p))
			.respond_with(ResponseTemplate::new(200).set_body_json(actor_token_body(token, 3600)))
			.expect(calls)
			.mount(&mock)
			.await;
	}
	Mock::given(method("POST"))
		.and(path("/token"))
		.respond_with(ResponseTemplate::new(200).set_body_json(token_body()))
		.expect(exchanges)
		.mount(&mock)
		.await;
	mock
}

#[tokio::test]
async fn actor_per_org_each_caller_gets_its_own_orgs_actor_cached_separately() {
	// Each org's actor is obtained once; org A's token is reused for A after B
	// was served, and never for B.
	let mock = mock_two_actors(1, 1, 3).await;
	let auth = backend_auth(OAuthTokenExchangeAuth {
		actor_token: Some(actor_per_org(endpoint(&mock))),
		..auth(endpoint(&mock))
	});

	for (subject, org) in [("alice", "org-a"), ("bob", "org-b"), ("carol", "org-a")] {
		crate::http::auth::apply_backend_auth(
			&backend_info(),
			&auth,
			&mut caller(subject, json!({ ORG_CLAIM: org })),
		)
		.await
		.unwrap();
	}

	let sent: Vec<(String, String)> = forms_sent_to(&mock, "/token")
		.await
		.into_iter()
		.map(|f| (f["subject_token"].clone(), f["actor_token"].clone()))
		.collect();
	assert_eq!(
		sent,
		vec![
			("alice".to_string(), "actor-token-org-a".to_string()),
			("bob".to_string(), "actor-token-org-b".to_string()),
			("carol".to_string(), "actor-token-org-a".to_string()),
		]
	);
	// Each org's own key signed its own assertion.
	for (p, client) in [("/actor-a", "actor-a"), ("/actor-b", "actor-b")] {
		let form = &forms_sent_to(&mock, p).await[0];
		#[derive(serde::Deserialize)]
		struct Iss {
			iss: String,
		}
		let claims: Iss = decode_unverified_jwt_claims(&form["assertion"]).unwrap();
		assert_eq!(claims.iss, client);
	}
}

#[rstest]
// The caller's org has no actor: refused, never sent with another org's.
#[case::org_without_actor(Some(json!({ ORG_CLAIM: "org-c" })))]
// The key expression fails (the claim is absent): refused.
#[case::claim_missing(Some(json!({"sub": "dave"})))]
// The key is not an org id (a number renders as "42"): it names no actor, refused.
#[case::claim_not_a_string(Some(json!({ ORG_CLAIM: 42 })))]
// No verified JWT at all: refused.
#[case::no_claims(None)]
#[tokio::test]
async fn actor_per_org_refuses_a_caller_it_cannot_place(#[case] claims: Option<serde_json::Value>) {
	let mock = mock_two_actors(0, 0, 0).await;
	let auth = backend_auth(OAuthTokenExchangeAuth {
		actor_token: Some(actor_per_org(endpoint(&mock))),
		..auth(endpoint(&mock))
	});
	let mut req = match claims {
		Some(c) => caller("dave", c),
		None => request_with_subject("dave"),
	};

	let result = crate::http::auth::apply_backend_auth(&backend_info(), &auth, &mut req).await;

	assert!(matches!(
		result.unwrap_err(),
		ProxyError::AuthorizationFailed
	));
	assert!(mock.received_requests().await.unwrap().is_empty());
	// The caller's own token is not forwarded either.
	assert_eq!(
		req.headers().get(::http::header::AUTHORIZATION).unwrap(),
		"Bearer dave"
	);
}

#[rstest]
#[case::empty_map(
	|e: Arc<SimpleBackendReference>| ActorTokenSpec {
		token_requests: Some(KeyedActorTokenRequests {
			key: Arc::new(cel::Expression::new_strict(r#""org-a""#).unwrap()),
			requests: BTreeMap::new(),
		}),
		..actor_per_org(e)
	},
	"at least one actor"
)]
#[case::with_single_request_too(
	|e: Arc<SimpleBackendReference>| ActorTokenSpec {
		token_request: Some(jwt_bearer_actor(e.clone())),
		..actor_per_org(e)
	},
	"exactly one of source, tokenRequest or tokenRequests"
)]
#[case::bad_entry(
	|e: Arc<SimpleBackendReference>| {
		let mut spec = actor_per_org(e);
		let keyed = spec.token_requests.as_mut().unwrap();
		keyed.requests.get_mut("org-b").unwrap().path = "relative".into();
		spec
	},
	r#"requests["org-b"]"#
)]
fn actor_per_org_validate_load(
	#[case] build: fn(Arc<SimpleBackendReference>) -> ActorTokenSpec,
	#[case] expected: &str,
) {
	let err = build(Arc::new(SimpleBackendReference::Invalid))
		.validate_load()
		.unwrap_err();
	assert!(err.contains(expected), "got: {err}");
}

#[test]
fn actor_per_org_deserializes_from_local_config() {
	let actor = |client: &str| {
		json!({
			"host": "issuer.example:443",
			"path": "/oauth/v2/token",
			"grantType": "jwtBearer",
			"clientAuth": {
				"method": "privateKeyJwt",
				"clientId": client,
				"signingKey": TEST_EC_PRIVATE_KEY_PEM,
				"alg": "ES256",
				"assertionAudience": "https://issuer.example",
			},
			"scopes": ["urn:zitadel:iam:org:project:id:mcp:aud"],
		})
	};
	let a: OAuthTokenExchangeAuth = serde_json::from_value(json!({
		"host": "issuer.example:443",
		"path": "/oauth/v2/token",
		"actorToken": {
			"tokenRequests": {
				"key": format!(r#"jwt["{ORG_CLAIM}"]"#),
				"requests": { "org-a": actor("actor-a"), "org-b": actor("actor-b") },
			},
		},
	}))
	.unwrap();
	a.validate_load().unwrap();
	let keyed = a.actor_token.unwrap().token_requests.unwrap();
	assert_eq!(
		keyed.requests.keys().collect::<Vec<_>>(),
		vec!["org-a", "org-b"]
	);
	assert_eq!(keyed.requests["org-b"].client_auth.client_id, "actor-b");
}

// ----- assertions signed by an OpenBao / Vault transit key (signer.vaultTransit) -----

struct TransitKey {
	encoding: jsonwebtoken::EncodingKey,
	public_pem: String,
}

fn transit_key() -> TransitKey {
	let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
	TransitKey {
		encoding: jsonwebtoken::EncodingKey::from_rsa_pem(pair.serialize_pem().as_bytes()).unwrap(),
		public_pem: pair.public_key_pem(),
	}
}

static ACTOR_KEY: std::sync::LazyLock<TransitKey> = std::sync::LazyLock::new(transit_key);
static OTHER_KEY: std::sync::LazyLock<TransitKey> = std::sync::LazyLock::new(transit_key);

/// `POST {mount}/sign/{key}` as the engine answers it: an RSASSA-PKCS1-v1_5 SHA-256
/// signature over the base64 `input`, as `vault:v1:<base64>`.
struct TransitSign(&'static TransitKey);

impl wiremock::Respond for TransitSign {
	fn respond(&self, req: &wiremock::Request) -> ResponseTemplate {
		let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
		let input = BASE64_STANDARD
			.decode(body["input"].as_str().unwrap())
			.unwrap();
		let signature =
			jsonwebtoken::crypto::sign(&input, &self.0.encoding, jsonwebtoken::Algorithm::RS256).unwrap();
		let raw = BASE64_URL_SAFE_NO_PAD.decode(signature).unwrap();
		ResponseTemplate::new(200).set_body_json(json!({
			"data": {"signature": format!("vault:v1:{}", BASE64_STANDARD.encode(raw))}
		}))
	}
}

fn engine_login_ok(token: &str, lease: u64) -> ResponseTemplate {
	ResponseTemplate::new(200)
		.set_body_json(json!({"auth": {"client_token": token, "lease_duration": lease}}))
}

/// The engine: a namespaced JWT login and the named keys' sign endpoints.
async fn mock_engine(
	login: ResponseTemplate,
	logins: u64,
	keys: &[(&str, &'static TransitKey)],
) -> MockServer {
	let engine = MockServer::start().await;
	Mock::given(method("POST"))
		.and(path("/v1/auth/jwt/login"))
		.and(wiremock::matchers::header("x-vault-namespace", "platform"))
		.respond_with(login)
		.expect(logins)
		.mount(&engine)
		.await;
	for (name, key) in keys {
		Mock::given(method("POST"))
			.and(path(format!("/v1/transit/sign/{name}")))
			.and(wiremock::matchers::header("x-vault-namespace", "platform"))
			.and(wiremock::matchers::header_exists("x-vault-token"))
			.respond_with(TransitSign(key))
			.mount(&engine)
			.await;
	}
	engine
}

/// The IdP: `/self` (the gateway's own token, for the engine login), `/actor`, `/token`.
async fn mock_idp(self_token: ResponseTemplate) -> MockServer {
	let idp = MockServer::start().await;
	Mock::given(method("POST"))
		.and(path("/self"))
		.respond_with(self_token)
		.mount(&idp)
		.await;
	Mock::given(method("POST"))
		.and(path("/actor"))
		.respond_with(
			ResponseTemplate::new(200).set_body_json(actor_token_body(GATEWAY_ACTOR_TOKEN, 3600)),
		)
		.mount(&idp)
		.await;
	Mock::given(method("POST"))
		.and(path("/token"))
		.respond_with(ResponseTemplate::new(200).set_body_json(token_body()))
		.mount(&idp)
		.await;
	idp
}

fn self_token_ok() -> ResponseTemplate {
	ResponseTemplate::new(200).set_body_json(actor_token_body("gateway-self-token", 3600))
}

fn transit_signer(engine: &MockServer, idp: &MockServer, key: &str) -> serde_json::Value {
	json!({"vaultTransit": {
		"address": format!("http://{}", engine.address()),
		"namespace": "platform",
		"key": key,
		"keyVersion": 1,
		"auth": {"jwt": {
			"role": "agentgateway",
			"tokenRequest": {
				"host": idp.address().to_string(),
				"path": "/self",
				"grantType": "jwtBearer",
				"clientAuth": {
					"method": "privateKeyJwt",
					"clientId": "gateway-user",
					"signingKey": TEST_EC_PRIVATE_KEY_PEM,
					"alg": "ES256",
					"assertionAudience": "https://issuer.example",
				},
				"scopes": ["openid"],
			},
		}},
	}})
}

fn transit_client_auth(signer: serde_json::Value, client_id: &str, kid: &str) -> OAuthClientAuth {
	serde_json::from_value(json!({
		"method": "privateKeyJwt",
		"clientId": client_id,
		"kid": kid,
		"assertionAudience": "https://issuer.example",
		"signer": signer,
	}))
	.unwrap()
}

fn transit_actor(idp: &MockServer, client_auth: OAuthClientAuth) -> ActorTokenRequest {
	ActorTokenRequest {
		client_auth,
		..actor_token_request(
			endpoint(idp),
			ActorTokenGrant::JwtBearer,
			gateway_client_secret(),
		)
	}
}

fn gateway_client_secret() -> OAuthClientAuth {
	OAuthClientAuth {
		client_id: "unused".into(),
		method: OAuthClientAuthMethod::ClientSecretBasic {
			client_secret: "unused".to_string().into(),
		},
	}
}

/// Verify an RS256 assertion with a transit key's PUBLIC key: issuer, subject, audience.
fn verify_assertion(assertion: &str, key: &TransitKey, client_id: &str) -> Result<(), String> {
	let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
	validation.set_audience(&["https://issuer.example"]);
	validation.set_issuer(&[client_id]);
	validation.sub = Some(client_id.to_string());
	jsonwebtoken::decode::<serde_json::Value>(
		assertion,
		&jsonwebtoken::DecodingKey::from_rsa_pem(key.public_pem.as_bytes()).unwrap(),
		&validation,
	)
	.map(|_| ())
	.map_err(|e| e.to_string())
}

async fn bodies_sent_to(server: &MockServer, to: &str) -> Vec<serde_json::Value> {
	server
		.received_requests()
		.await
		.unwrap()
		.iter()
		.filter(|r| r.url.path() == to)
		.map(|r| serde_json::from_slice(&r.body).unwrap())
		.collect()
}

#[tokio::test]
async fn transit_signer_signs_the_actor_assertion_with_its_named_key() {
	let engine = mock_engine(
		engine_login_ok("engine-token-1", 600),
		1,
		&[("actor-notarik", &ACTOR_KEY), ("app", &OTHER_KEY)],
	)
	.await;
	let idp = mock_idp(self_token_ok()).await;
	let actor = transit_actor(
		&idp,
		transit_client_auth(
			transit_signer(&engine, &idp, "actor-notarik"),
			"actor-notarik-user",
			"actor-notarik-kid",
		),
	);
	let a = OAuthTokenExchangeAuth {
		actor_token: Some(gateway_actor(actor, OAuthTokenType::AccessToken)),
		..auth(endpoint(&idp))
	};

	crate::http::auth::apply_backend_auth(
		&backend_info(),
		&backend_auth(a),
		&mut request_with_subject("subj"),
	)
	.await
	.unwrap();

	// The engine login: the gateway's own token, the role, in the namespace.
	let login = &bodies_sent_to(&engine, "/v1/auth/jwt/login").await[0];
	assert_eq!(login["role"], "agentgateway");
	assert_eq!(login["jwt"], "gateway-self-token");
	// The sign call: the named key, the declared algorithms, the base64 signing input.
	let sign = &bodies_sent_to(&engine, "/v1/transit/sign/actor-notarik").await[0];
	assert_eq!(sign["hash_algorithm"], "sha2-256");
	assert_eq!(sign["signature_algorithm"], "pkcs1v15");
	assert_eq!(sign["prehashed"], false);
	assert!(
		bodies_sent_to(&engine, "/v1/transit/sign/app")
			.await
			.is_empty()
	);
	let sign_req = engine
		.received_requests()
		.await
		.unwrap()
		.into_iter()
		.find(|r| r.url.path() == "/v1/transit/sign/actor-notarik")
		.unwrap();
	assert_eq!(
		sign_req.headers.get("x-vault-token").unwrap(),
		"engine-token-1"
	);

	// The actor assertion verifies with the transit key's public key, and only that key.
	let assertion = forms_sent_to(&idp, "/actor").await[0]["assertion"].clone();
	let (signing_input, _) = assertion.rsplit_once('.').unwrap();
	assert_eq!(
		BASE64_STANDARD
			.decode(sign["input"].as_str().unwrap())
			.unwrap(),
		signing_input.as_bytes()
	);
	verify_assertion(&assertion, &ACTOR_KEY, "actor-notarik-user").unwrap();
	assert!(verify_assertion(&assertion, &OTHER_KEY, "actor-notarik-user").is_err());
	let header = jsonwebtoken::decode_header(&assertion).unwrap();
	assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
	assert_eq!(header.kid.as_deref(), Some("actor-notarik-kid"));
	assert_eq!(
		forms_sent_to(&idp, "/token").await[0]["actor_token"],
		GATEWAY_ACTOR_TOKEN
	);
}

#[tokio::test]
async fn transit_signer_signs_the_exchanging_apps_client_assertion() {
	let engine = mock_engine(
		engine_login_ok("engine-token-1", 600),
		1,
		&[("app", &OTHER_KEY)],
	)
	.await;
	let idp = mock_idp(self_token_ok()).await;
	let a = OAuthTokenExchangeAuth {
		client_auth: Some(transit_client_auth(
			transit_signer(&engine, &idp, "app"),
			"app-client",
			"app-kid",
		)),
		..auth(endpoint(&idp))
	};

	crate::http::auth::apply_backend_auth(
		&backend_info(),
		&backend_auth(a),
		&mut request_with_subject("subj"),
	)
	.await
	.unwrap();

	let exchange = &forms_sent_to(&idp, "/token").await[0];
	assert_eq!(exchange["client_id"], "app-client");
	assert_eq!(
		exchange["client_assertion_type"],
		CLIENT_ASSERTION_TYPE_JWT_BEARER
	);
	verify_assertion(&exchange["client_assertion"], &OTHER_KEY, "app-client").unwrap();
}

#[rstest]
// A token well inside its lease serves every signature.
#[case::reused_while_fresh(3600, 1)]
// A token inside the refresh margin is never reused: each signature logs in again.
#[case::renewed_near_expiry(1, 2)]
#[tokio::test]
async fn transit_engine_token_is_cached_then_renewed(#[case] lease: u64, #[case] logins: u64) {
	let engine = mock_engine(
		engine_login_ok("engine-token-1", lease),
		logins,
		&[("app", &OTHER_KEY)],
	)
	.await;
	let idp = mock_idp(self_token_ok()).await;
	let auth = backend_auth(OAuthTokenExchangeAuth {
		client_auth: Some(transit_client_auth(
			transit_signer(&engine, &idp, "app"),
			"app-client",
			"app-kid",
		)),
		..auth(endpoint(&idp))
	});
	// Two callers: two exchanges, two client assertions to sign.
	for subject in ["subj-a", "subj-b"] {
		crate::http::auth::apply_backend_auth(
			&backend_info(),
			&auth,
			&mut request_with_subject(subject),
		)
		.await
		.unwrap();
	}
	assert_eq!(
		bodies_sent_to(&engine, "/v1/transit/sign/app").await.len(),
		2
	);
}

#[tokio::test]
async fn transit_refused_engine_token_logs_in_again_once() {
	let engine = MockServer::start().await;
	Mock::given(method("POST"))
		.and(path("/v1/auth/jwt/login"))
		.respond_with(engine_login_ok("engine-token-stale", 600))
		.up_to_n_times(1)
		.with_priority(1)
		.mount(&engine)
		.await;
	Mock::given(method("POST"))
		.and(path("/v1/auth/jwt/login"))
		.respond_with(engine_login_ok("engine-token-fresh", 600))
		.with_priority(2)
		.mount(&engine)
		.await;
	Mock::given(method("POST"))
		.and(path("/v1/transit/sign/app"))
		.and(wiremock::matchers::header(
			"x-vault-token",
			"engine-token-stale",
		))
		.respond_with(
			ResponseTemplate::new(403).set_body_json(json!({"errors": ["permission denied"]})),
		)
		.mount(&engine)
		.await;
	Mock::given(method("POST"))
		.and(path("/v1/transit/sign/app"))
		.and(wiremock::matchers::header(
			"x-vault-token",
			"engine-token-fresh",
		))
		.respond_with(TransitSign(&OTHER_KEY))
		.mount(&engine)
		.await;
	let idp = mock_idp(self_token_ok()).await;
	let mut signer = transit_signer(&engine, &idp, "app");
	signer["vaultTransit"]
		.as_object_mut()
		.unwrap()
		.remove("namespace");
	let a = OAuthTokenExchangeAuth {
		client_auth: Some(transit_client_auth(signer, "app-client", "app-kid")),
		..auth(endpoint(&idp))
	};

	crate::http::auth::apply_backend_auth(
		&backend_info(),
		&backend_auth(a),
		&mut request_with_subject("subj"),
	)
	.await
	.unwrap();

	assert_eq!(bodies_sent_to(&engine, "/v1/auth/jwt/login").await.len(), 2);
	verify_assertion(
		&forms_sent_to(&idp, "/token").await[0]["client_assertion"],
		&OTHER_KEY,
		"app-client",
	)
	.unwrap();
}

#[rstest]
// The engine will not sign.
#[case::sign_fails(
	ResponseTemplate::new(500),
	engine_login_ok("engine-token-1", 600),
	self_token_ok(),
	1
)]
// The engine refuses every token: one fresh login, then refused (no loop).
#[case::sign_always_refused(
	ResponseTemplate::new(403),
	engine_login_ok("engine-token-1", 600),
	self_token_ok(),
	2
)]
// The engine login is refused.
#[case::login_refused(ResponseTemplate::new(200), ResponseTemplate::new(400).set_body_json(json!({"errors": ["role not found"]})), self_token_ok(), 1)]
// The gateway cannot obtain its own token for the login.
#[case::self_token_fails(
	ResponseTemplate::new(200),
	engine_login_ok("engine-token-1", 600),
	ResponseTemplate::new(500),
	0
)]
#[tokio::test]
async fn transit_signer_failure_fails_closed(
	#[case] sign: ResponseTemplate,
	#[case] login: ResponseTemplate,
	#[case] self_token: ResponseTemplate,
	#[case] logins: u64,
) {
	let engine = MockServer::start().await;
	Mock::given(method("POST"))
		.and(path("/v1/auth/jwt/login"))
		.respond_with(login)
		.expect(logins)
		.mount(&engine)
		.await;
	Mock::given(method("POST"))
		.and(path("/v1/transit/sign/actor-notarik"))
		.respond_with(sign)
		.mount(&engine)
		.await;
	let idp = mock_idp(self_token).await;
	let a = OAuthTokenExchangeAuth {
		actor_token: Some(gateway_actor(
			transit_actor(
				&idp,
				transit_client_auth(
					transit_signer(&engine, &idp, "actor-notarik"),
					"actor-notarik-user",
					"actor-notarik-kid",
				),
			),
			OAuthTokenType::AccessToken,
		)),
		..auth(endpoint(&idp))
	};
	let mut req = request_with_subject("subj");

	let result =
		crate::http::auth::apply_backend_auth(&backend_info(), &backend_auth(a), &mut req).await;

	assert!(result.is_err());
	// No assertion was sent anywhere, so nothing was exchanged.
	assert!(forms_sent_to(&idp, "/actor").await.is_empty());
	assert!(forms_sent_to(&idp, "/token").await.is_empty());
}

#[tokio::test]
async fn transit_signer_per_org_each_actor_signs_with_its_own_key() {
	let engine = mock_engine(
		engine_login_ok("engine-token-1", 600),
		2,
		&[("actor-a", &ACTOR_KEY), ("actor-b", &OTHER_KEY)],
	)
	.await;
	let idp = mock_idp(self_token_ok()).await;
	let org_actor = |org: &str, key: &str| ActorTokenRequest {
		path: format!("/actor-{org}"),
		..transit_actor(
			&idp,
			transit_client_auth(
				transit_signer(&engine, &idp, key),
				&format!("{key}-user"),
				key,
			),
		)
	};
	for org in ["a", "b"] {
		Mock::given(method("POST"))
			.and(path(format!("/actor-{org}")))
			.respond_with(
				ResponseTemplate::new(200)
					.set_body_json(actor_token_body(&format!("actor-token-{org}"), 3600)),
			)
			.mount(&idp)
			.await;
	}
	let auth = backend_auth(OAuthTokenExchangeAuth {
		actor_token: Some(ActorTokenSpec {
			source: None,
			token_request: None,
			token_requests: Some(KeyedActorTokenRequests {
				key: Arc::new(cel::Expression::new_strict(format!(r#"jwt["{ORG_CLAIM}"]"#)).unwrap()),
				requests: BTreeMap::from([
					("org-a".to_string(), org_actor("a", "actor-a")),
					("org-b".to_string(), org_actor("b", "actor-b")),
				]),
			}),
			token_type: OAuthTokenType::AccessToken,
			enforce_may_act: false,
		}),
		..auth(endpoint(&idp))
	});

	for (subject, org) in [("alice", "org-a"), ("bob", "org-b")] {
		crate::http::auth::apply_backend_auth(
			&backend_info(),
			&auth,
			&mut caller(subject, json!({ ORG_CLAIM: org })),
		)
		.await
		.unwrap();
	}

	let a = forms_sent_to(&idp, "/actor-a").await[0]["assertion"].clone();
	let b = forms_sent_to(&idp, "/actor-b").await[0]["assertion"].clone();
	verify_assertion(&a, &ACTOR_KEY, "actor-a-user").unwrap();
	verify_assertion(&b, &OTHER_KEY, "actor-b-user").unwrap();
	assert!(verify_assertion(&a, &OTHER_KEY, "actor-a-user").is_err());
	assert!(verify_assertion(&b, &ACTOR_KEY, "actor-b-user").is_err());
}

#[rstest]
#[case::key_and_signer(json!({"signingKey": TEST_EC_PRIVATE_KEY_PEM, "alg": "ES256"}), "exactly one of signing_key or signer")]
#[case::not_rs256(json!({"alg": "ES256"}), "RS256 only")]
#[case::certificate(json!({"certificate": TEST_EC_CERT_PEM, "certificateHeader": "x5c"}), "certificate")]
#[case::empty_key(json!({"signer": {"vaultTransit": {"key": ""}}}), "key must not be empty")]
#[case::key_version_zero(json!({"signer": {"vaultTransit": {"keyVersion": 0}}}), "keyVersion must be 1 or more")]
// A shape error is refused by clientAuth's untagged parse, which reports it generically.
#[case::key_version_unset(json!({"signer": {"vaultTransit": {"keyVersion": null}}}), "did not match any variant")]
#[case::auth_not_tagged(json!({"signer": {"vaultTransit": {"auth": {"role": "agentgateway"}}}}), "did not match any variant")]
#[case::key_is_a_path(json!({"signer": {"vaultTransit": {"key": "a/b"}}}), "key must be a key name")]
#[case::login_by_signer(
	json!({"signer": {"vaultTransit": {"auth": {"jwt": {"tokenRequest": {"clientAuth": {
		"signingKey": null, "alg": "RS256",
		"signer": {"vaultTransit": {"address": "http://127.0.0.1:1", "key": "self", "keyVersion": 1, "auth": {"jwt": {"role": "r", "tokenRequest": {
			"host": "127.0.0.1:1", "grantType": "clientCredentials",
			"clientAuth": {"clientId": "c", "clientSecret": "s"}}}}}},
	}}}}}}}),
	"must hold its own signingKey"
)]
fn transit_signer_validate_load(#[case] patch: serde_json::Value, #[case] expected: &str) {
	let mut config = json!({
		"method": "privateKeyJwt",
		"clientId": "actor-notarik-user",
		"assertionAudience": "https://issuer.example",
		"signer": {"vaultTransit": {
			"address": "http://127.0.0.1:1",
			"key": "actor-notarik",
			"keyVersion": 1,
			"auth": {"jwt": {"role": "agentgateway", "tokenRequest": {
				"host": "127.0.0.1:1",
				"grantType": "jwtBearer",
				"clientAuth": {
					"method": "privateKeyJwt", "clientId": "gateway-user",
					"signingKey": TEST_EC_PRIVATE_KEY_PEM, "alg": "ES256",
					"assertionAudience": "https://issuer.example",
				},
			}}},
		}},
	});
	json_patch_merge(&mut config, patch);
	let err = serde_json::from_value::<OAuthClientAuth>(config).unwrap_err();
	assert!(err.to_string().contains(expected), "got: {err}");
}

/// RFC 7386 merge patch, for building config variants.
fn json_patch_merge(target: &mut serde_json::Value, patch: serde_json::Value) {
	match (target, patch) {
		(serde_json::Value::Object(t), serde_json::Value::Object(p)) => {
			for (k, v) in p {
				json_patch_merge(t.entry(k).or_insert(serde_json::Value::Null), v);
			}
		},
		(t, p) => *t = p,
	}
}

#[tokio::test]
async fn transit_signer_tokens_never_appear_in_debug_output() {
	let engine = mock_engine(
		engine_login_ok("engine-token-secret-1", 600),
		1,
		&[("app", &OTHER_KEY)],
	)
	.await;
	let idp = mock_idp(self_token_ok()).await;
	let a = OAuthTokenExchangeAuth {
		client_auth: Some(transit_client_auth(
			transit_signer(&engine, &idp, "app"),
			"app-client",
			"app-kid",
		)),
		..auth(endpoint(&idp))
	};
	let auth = backend_auth(a.clone());
	crate::http::auth::apply_backend_auth(&backend_info(), &auth, &mut request_with_subject("subj"))
		.await
		.unwrap();
	for debug in [format!("{a:?}"), format!("{auth:?}")] {
		assert!(!debug.contains("engine-token-secret-1"), "{debug}");
		assert!(!debug.contains("gateway-self-token"), "{debug}");
		assert!(!debug.contains("PRIVATE KEY"), "{debug}");
		assert!(debug.contains("VaultTransitSigner"), "{debug}");
	}
}

/// A transit key with two versions: signs with the requested `key_version`, or the
/// latest when none is named, and says which in the `vault:vN:` prefix.
struct TransitVersions {
	versions: [(u32, &'static TransitKey); 2],
	/// Answer as this version whatever was asked (a mis-behaving engine).
	claim: Option<u32>,
}

impl wiremock::Respond for TransitVersions {
	fn respond(&self, req: &wiremock::Request) -> ResponseTemplate {
		let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
		let wanted = body["key_version"]
			.as_u64()
			.map(|v| v as u32)
			.unwrap_or(self.versions[1].0);
		let (version, key) = *self.versions.iter().find(|(v, _)| *v == wanted).unwrap();
		let input = BASE64_STANDARD
			.decode(body["input"].as_str().unwrap())
			.unwrap();
		let signature =
			jsonwebtoken::crypto::sign(&input, &key.encoding, jsonwebtoken::Algorithm::RS256).unwrap();
		let raw = BASE64_URL_SAFE_NO_PAD.decode(signature).unwrap();
		ResponseTemplate::new(200).set_body_json(json!({
			"data": {"signature": format!("vault:v{}:{}", self.claim.unwrap_or(version), BASE64_STANDARD.encode(raw))}
		}))
	}
}

async fn engine_with_versions(claim: Option<u32>) -> MockServer {
	let engine = MockServer::start().await;
	Mock::given(method("POST"))
		.and(path("/v1/auth/jwt/login"))
		.respond_with(engine_login_ok("engine-token-1", 600))
		.mount(&engine)
		.await;
	Mock::given(method("POST"))
		.and(path("/v1/transit/sign/app"))
		.respond_with(TransitVersions {
			versions: [(1, &ACTOR_KEY), (2, &OTHER_KEY)],
			claim,
		})
		.mount(&engine)
		.await;
	engine
}

#[tokio::test]
async fn transit_signer_signs_with_the_pinned_key_version_not_the_latest() {
	// The key was rotated to v2; the config (and the IdP's registered kid) still pin v1.
	let engine = engine_with_versions(None).await;
	let idp = mock_idp(self_token_ok()).await;
	let a = OAuthTokenExchangeAuth {
		client_auth: Some(transit_client_auth(
			transit_signer(&engine, &idp, "app"),
			"app-client",
			"app-kid-v1",
		)),
		..auth(endpoint(&idp))
	};

	crate::http::auth::apply_backend_auth(
		&backend_info(),
		&backend_auth(a),
		&mut request_with_subject("subj"),
	)
	.await
	.unwrap();

	assert_eq!(
		bodies_sent_to(&engine, "/v1/transit/sign/app").await[0]["key_version"],
		1
	);
	let assertion = &forms_sent_to(&idp, "/token").await[0]["client_assertion"];
	verify_assertion(assertion, &ACTOR_KEY, "app-client").unwrap();
	assert!(verify_assertion(assertion, &OTHER_KEY, "app-client").is_err());
	assert_eq!(
		jsonwebtoken::decode_header(assertion)
			.unwrap()
			.kid
			.as_deref(),
		Some("app-kid-v1")
	);
}

#[tokio::test]
async fn transit_signature_from_another_version_is_refused() {
	// The engine answers with a v2 signature to a v1 request: nothing is sent.
	let engine = engine_with_versions(Some(2)).await;
	let idp = mock_idp(self_token_ok()).await;
	let a = OAuthTokenExchangeAuth {
		client_auth: Some(transit_client_auth(
			transit_signer(&engine, &idp, "app"),
			"app-client",
			"app-kid-v1",
		)),
		..auth(endpoint(&idp))
	};

	let result = crate::http::auth::apply_backend_auth(
		&backend_info(),
		&backend_auth(a),
		&mut request_with_subject("subj"),
	)
	.await;

	assert!(result.is_err());
	assert!(forms_sent_to(&idp, "/token").await.is_empty());
}
