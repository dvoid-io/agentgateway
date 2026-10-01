//! Signing with a key held in an OpenBao / HashiCorp Vault transit engine.
//!
//! The gateway never holds the private key: it sends the JWS signing input to
//! `POST /v1/{mount}/sign/{key}` and receives the signature. It authenticates to
//! the engine with a JWT auth login (`POST /v1/auth/{path}/login`), presenting a
//! token it obtains itself from `tokenRequest`; the engine token is cached until
//! shortly before it expires, and a rejected one is replaced once.

use std::fmt;

use ::http::StatusCode;
use ::http::header::{ACCEPT, CONTENT_TYPE};
use anyhow::{Context, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, trace};

use super::cache::{self, InMemoryTokenCache, TokenCacheResult};
use super::transport::TokenEndpointResponse;
use super::{ActorTokenRequest, ExchangeRequest, OAuthClientAuthMethod};
use crate::http::filters::BackendRequestTimeout;
use crate::http::{self, Body};
use crate::json;
use crate::proxy::httpproxy::PolicyClient;
use crate::telemetry::metrics::{OutboundCallKind, OutboundCallSubtype};
use crate::types::agent::SimpleBackendReferenceWithPolicies;

const ENGINE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// `signer.vaultTransit`: an OpenBao / Vault transit key signs the assertion.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub(super) struct RawVaultTransitSigner {
	/// Base URL of the engine, e.g. `https://bao.example.com` (https gets backend TLS).
	address: String,
	/// `X-Vault-Namespace` for every call, when the key lives in a namespace.
	#[serde(default)]
	namespace: Option<String>,
	/// Mount path of the transit engine; defaults to `transit`.
	#[serde(default = "default_transit_mount")]
	mount: String,
	/// Name of the transit key. Only RSA keys with `alg: RS256` are supported.
	key: String,
	/// The key version to sign with, sent as `key_version`. Pinned, never the
	/// latest: an IdP that picks the verifying key by `kid` refuses a signature
	/// from any other version, so a rotation must change both together.
	key_version: u32,
	/// How the gateway authenticates to the engine.
	auth: RawVaultAuth,
}

/// The engine auth method; one of its fields must be set.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub(super) struct RawVaultAuth {
	/// JWT auth: `POST /v1/auth/{path}/login {role, jwt}`.
	jwt: RawVaultJwtLogin,
}

fn default_transit_mount() -> String {
	"transit".into()
}

/// A JWT auth login at the engine.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub(super) struct RawVaultJwtLogin {
	/// Mount path of the JWT auth method; defaults to `jwt`.
	#[serde(default = "default_jwt_path")]
	path: String,
	/// Role to log in as.
	role: String,
	/// The gateway's own token, presented as the login `jwt`. Same fields as
	/// `actorToken.tokenRequest`; its `clientAuth` must hold its own key
	/// (`signingKey`), never a `signer`.
	#[cfg_attr(
		feature = "schema",
		schemars(with = "serde_json::Map<String, serde_json::Value>")
	)]
	token_request: Box<ActorTokenRequest>,
}

fn default_jwt_path() -> String {
	"jwt".into()
}

#[derive(Clone)]
pub(super) struct VaultTransitSigner {
	target: SimpleBackendReferenceWithPolicies,
	address: String,
	namespace: Option<String>,
	mount: String,
	key: String,
	key_version: u32,
	login_path: String,
	login_role: String,
	login_token_request: Box<ActorTokenRequest>,
	// One entry: the engine token does not depend on the request.
	engine_token: InMemoryTokenCache,
}

impl fmt::Debug for VaultTransitSigner {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("VaultTransitSigner")
			.field("address", &self.address)
			.field("namespace", &self.namespace)
			.field("mount", &self.mount)
			.field("key", &self.key)
			.field("key_version", &self.key_version)
			.field("login_path", &self.login_path)
			.field("login_role", &self.login_role)
			.finish_non_exhaustive()
	}
}

impl TryFrom<RawVaultTransitSigner> for VaultTransitSigner {
	type Error = String;

	fn try_from(raw: RawVaultTransitSigner) -> Result<Self, Self::Error> {
		let target: SimpleBackendReferenceWithPolicies =
			serde_json::from_value(json!({ "host": raw.address }))
				.map_err(|e| format!("signer.vaultTransit.address: {e}"))?;
		for (field, value) in [
			("mount", &raw.mount),
			("key", &raw.key),
			("auth.jwt.path", &raw.auth.jwt.path),
			("auth.jwt.role", &raw.auth.jwt.role),
		] {
			if value.trim().is_empty() {
				return Err(format!("signer.vaultTransit.{field} must not be empty"));
			}
		}
		if raw.key_version == 0 {
			return Err("signer.vaultTransit.keyVersion must be 1 or more".into());
		}
		if raw.key.contains('/') {
			return Err("signer.vaultTransit.key must be a key name, not a path".into());
		}
		raw
			.auth
			.jwt
			.token_request
			.validate_load()
			.map_err(|e| format!("signer.vaultTransit.auth.jwt.tokenRequest: {e}"))?;
		// The login credential is the secret zero: it cannot itself be a signer,
		// or signing would need a login that needs signing.
		if let OAuthClientAuthMethod::PrivateKeyJwt(key) =
			&raw.auth.jwt.token_request.client_auth.method
			&& key.is_external()
		{
			return Err(
				"signer.vaultTransit.auth.jwt.tokenRequest.clientAuth must hold its own signingKey, not a signer"
					.into(),
			);
		}
		Ok(Self {
			target,
			address: raw.address,
			namespace: raw.namespace.filter(|n| !n.is_empty()),
			mount: raw.mount.trim_matches('/').to_string(),
			key: raw.key,
			key_version: raw.key_version,
			login_path: raw.auth.jwt.path.trim_matches('/').to_string(),
			login_role: raw.auth.jwt.role,
			login_token_request: raw.auth.jwt.token_request,
			engine_token: InMemoryTokenCache::new(1, cache::DEFAULT_CACHE_TTL),
		})
	}
}

/// Why a sign call failed: the engine refused the token (log in again), or anything else.
enum SignError {
	Forbidden,
	Other(anyhow::Error),
}

impl VaultTransitSigner {
	/// The base64url signature of `input` (a JWS signing input), RSASSA-PKCS1-v1_5
	/// with SHA-256. A token the engine refuses is replaced once; any other
	/// failure is returned, and nothing is signed any other way.
	pub(super) async fn sign(&self, client: &PolicyClient, input: &[u8]) -> anyhow::Result<String> {
		for attempt in 0..2 {
			let token = self.engine_token(client).await?;
			match self.sign_with(client, &token, input).await {
				Ok(signature) => return Ok(signature),
				Err(SignError::Forbidden) if attempt == 0 => {
					debug!(key = %self.key, "transit refused the engine token; logging in again");
					self.engine_token.invalidate(&ExchangeRequest::default());
				},
				Err(SignError::Forbidden) => bail!("transit refused a fresh engine token"),
				Err(SignError::Other(e)) => return Err(e),
			}
		}
		unreachable!("the loop returns on its second attempt")
	}

	async fn engine_token(&self, client: &PolicyClient) -> anyhow::Result<SecretString> {
		let result = self
			.engine_token
			.get_or_insert_with(&ExchangeRequest::default(), || self.login(client))
			.await?;
		match &result {
			TokenCacheResult::Hit(_) => trace!("transit engine token cache hit"),
			TokenCacheResult::Miss(_) => trace!("transit engine login"),
		}
		Ok(result.into_token())
	}

	async fn login(&self, client: &PolicyClient) -> anyhow::Result<TokenEndpointResponse> {
		// Boxed: the login's token request can be signed, so the future types
		// recurse (a signer's login cannot itself use a signer; load refuses it).
		let jwt = Box::pin(self.login_token_request.fetch(client))
			.await
			.map_err(|e| anyhow!("could not obtain the token for the transit login: {e}"))?;
		let body = json!({ "role": self.login_role, "jwt": jwt.expose_secret() });
		let (status, resp) = self
			.call(
				client,
				&format!("/v1/auth/{}/login", self.login_path),
				None,
				body,
			)
			.await?;
		if !status.is_success() {
			bail!("transit login returned status {status}");
		}
		#[derive(Deserialize)]
		struct Login {
			auth: LoginAuth,
		}
		#[derive(Deserialize)]
		struct LoginAuth {
			client_token: SecretString,
			#[serde(default)]
			lease_duration: Option<u64>,
		}
		let limit = http::response_buffer_limit(&resp);
		let login: Login = json::from_body_with_limit(resp.into_body(), limit)
			.await
			.context("transit login response")?;
		if login.auth.client_token.expose_secret().is_empty() {
			bail!("transit login returned an empty token");
		}
		Ok(TokenEndpointResponse {
			access_token: login.auth.client_token,
			expires_in: login.auth.lease_duration.filter(|d| *d > 0),
		})
	}

	async fn sign_with(
		&self,
		client: &PolicyClient,
		token: &SecretString,
		input: &[u8],
	) -> Result<String, SignError> {
		let body = json!({
			"input": STANDARD.encode(input),
			"key_version": self.key_version,
			"hash_algorithm": "sha2-256",
			"signature_algorithm": "pkcs1v15",
			"prehashed": false,
		});
		let (status, resp) = self
			.call(
				client,
				&format!("/v1/{}/sign/{}", self.mount, self.key),
				Some(token),
				body,
			)
			.await
			.map_err(SignError::Other)?;
		match status {
			StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => return Err(SignError::Forbidden),
			s if !s.is_success() => {
				return Err(SignError::Other(anyhow!(
					"transit sign returned status {s}"
				)));
			},
			_ => {},
		}
		#[derive(Deserialize)]
		struct Sign {
			data: SignData,
		}
		#[derive(Deserialize)]
		struct SignData {
			signature: String,
		}
		let limit = http::response_buffer_limit(&resp);
		let sign: Sign = json::from_body_with_limit(resp.into_body(), limit)
			.await
			.context("transit sign response")
			.map_err(SignError::Other)?;
		let (version, signature) = jws_signature(&sign.data.signature).map_err(SignError::Other)?;
		if version != self.key_version {
			return Err(SignError::Other(anyhow!(
				"transit signed with key version {version}, not the pinned {}",
				self.key_version
			)));
		}
		Ok(signature)
	}

	async fn call(
		&self,
		client: &PolicyClient,
		path: &str,
		token: Option<&SecretString>,
		body: serde_json::Value,
	) -> anyhow::Result<(StatusCode, ::http::Response<Body>)> {
		let mut builder = ::http::Request::builder()
			.method(::http::Method::POST)
			.uri(path)
			.header(CONTENT_TYPE, "application/json")
			.header(ACCEPT, "application/json");
		if let Some(namespace) = &self.namespace {
			builder = builder.header("x-vault-namespace", namespace);
		}
		if let Some(token) = token {
			builder = builder.header("x-vault-token", token.expose_secret());
		}
		let mut req = builder.body(Body::from(serde_json::to_vec(&body)?))?;
		req
			.extensions_mut()
			.insert(BackendRequestTimeout(ENGINE_TIMEOUT));
		let resp = client
			.with_outbound(OutboundCallKind::Policy, OutboundCallSubtype::Oidc)
			.call_reference_with_policies(req, self.target.target.as_ref(), &self.target.policies)
			.await
			.map_err(|e| anyhow!("transit request failed: {e}"))?;
		Ok((resp.status(), resp))
	}
}

/// A transit signature (`vault:v<N>:<base64>`) as its key version and a JWS
/// signature (base64url, no padding).
fn jws_signature(transit: &str) -> anyhow::Result<(u32, String)> {
	let mut parts = transit.splitn(3, ':');
	let (Some("vault"), Some(version), Some(signature)) = (parts.next(), parts.next(), parts.next())
	else {
		bail!("transit signature is not in the vault:v<N>:<base64> form");
	};
	let Some(version) = version
		.strip_prefix('v')
		.filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
		.and_then(|n| n.parse::<u32>().ok())
	else {
		bail!("transit signature has no key version");
	};
	let raw = STANDARD
		.decode(signature)
		.context("transit signature is not base64")?;
	Ok((version, URL_SAFE_NO_PAD.encode(raw)))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn jws_signature_strips_the_version_and_re_encodes() {
		let raw = [0xfbu8, 0xff, 0x3e, 0x00, 0x7f];
		let transit = format!("vault:v12:{}", STANDARD.encode(raw));
		assert_eq!(
			jws_signature(&transit).unwrap(),
			(12, URL_SAFE_NO_PAD.encode(raw))
		);
		for bad in [
			"abc",
			"vault:v1",
			"vault:x1:AAAA",
			"vault:v:AAAA",
			"vault:v1:not*base64",
			"hvs:v1:AAAA",
		] {
			assert!(jws_signature(bad).is_err(), "{bad}");
		}
	}
}
