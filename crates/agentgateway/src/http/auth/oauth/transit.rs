//! Signing with a key held in an OpenBao / HashiCorp Vault transit engine.
//!
//! The gateway never holds the private key: it sends the JWS signing input to
//! `POST /v1/{mount}/sign/{key}` and receives the signature. It authenticates to
//! the engine with a JWT auth login (`POST /v1/auth/{path}/login`), presenting a
//! token it obtains itself from `tokenRequest`; the engine token is cached until
//! shortly before it expires, and a rejected one is replaced once.
//!
//! The key version, and the `kid` that names it at the IdP, are either pinned in
//! the configuration (`keyVersion` with `clientAuth.kid`) or read at runtime from
//! a KV v2 secret the rotation publishes them to (`publishedPair`), so a key
//! rotates without a restart. The two always travel together: an IdP that picks
//! the verifying key by `kid` refuses a signature from any other version.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ::http::StatusCode;
use ::http::header::{ACCEPT, CONTENT_TYPE};
use anyhow::{Context, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use parking_lot::Mutex;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, info, trace, warn};

use super::cache::{self, InMemoryTokenCache, TokenCacheResult};
use super::transport::TokenEndpointResponse;
use super::{ActorTokenRequest, ExchangeRequest, OAuthClientAuthMethod};
use crate::http::filters::BackendRequestTimeout;
use crate::http::{self, Body};
use crate::json;
use crate::proxy::httpproxy::PolicyClient;
use crate::telemetry::metrics::{OutboundCallKind, OutboundCallSubtype};
use crate::types::agent::SimpleBackendReferenceWithPolicies;

const ENGINE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a published pair is used before the next signature reads it again.
const DEFAULT_PAIR_REFRESH: Duration = Duration::from_secs(60);

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
	/// The key version to sign with, sent as `key_version`, with `clientAuth.kid`
	/// naming it. Pinned, never the latest: an IdP that picks the verifying key by
	/// `kid` refuses a signature from any other version, so a rotation must change
	/// both together. Exactly one of `keyVersion` or `publishedPair` must be set.
	#[serde(default)]
	key_version: Option<u32>,
	/// Read the version and its `kid` at runtime instead, from a KV v2 secret the
	/// rotation publishes them to; `clientAuth.kid` must then be unset.
	#[serde(default)]
	published_pair: Option<RawPublishedPair>,
	/// How the gateway authenticates to the engine.
	auth: RawVaultAuth,
}

/// A KV v2 secret holding the key version to sign with and the `kid` naming it:
/// `{"key_version": 3, "key_id": "..."}` (the version as a number or a string of
/// digits). It is read through the same engine login and namespace as the sign
/// calls. A read that fails keeps the last pair read; with none yet, nothing is
/// signed. Nothing is ever signed under a guessed version or `kid`.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub(super) struct RawPublishedPair {
	/// API path of the secret, mount included, e.g. `kv/data/broker/app`.
	path: String,
	/// How long a pair is used before the next signature reads it again;
	/// defaults to 60s. `0s` reads it for every signature.
	#[serde(default, with = "crate::serdes::serde_dur_option")]
	#[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
	refresh: Option<Duration>,
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
	version: VersionSource,
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
			.field("version", &self.version)
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
		let version = match (raw.key_version, raw.published_pair) {
			(Some(_), Some(_)) => {
				return Err(
					"signer.vaultTransit: set exactly one of keyVersion or publishedPair, not both".into(),
				);
			},
			(None, None) => {
				return Err("signer.vaultTransit: one of keyVersion or publishedPair must be set".into());
			},
			(Some(0), None) => return Err("signer.vaultTransit.keyVersion must be 1 or more".into()),
			(Some(v), None) => VersionSource::Pinned(v),
			(None, Some(published)) => {
				let path = published.path.trim_matches('/').to_string();
				if path.is_empty() {
					return Err("signer.vaultTransit.publishedPair.path must not be empty".into());
				}
				VersionSource::Published(Arc::new(PublishedPair {
					path,
					refresh: published.refresh.unwrap_or(DEFAULT_PAIR_REFRESH),
					last: Mutex::new(None),
				}))
			},
		};
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
			version,
			login_path: raw.auth.jwt.path.trim_matches('/').to_string(),
			login_role: raw.auth.jwt.role,
			login_token_request: raw.auth.jwt.token_request,
			engine_token: InMemoryTokenCache::new(1, cache::DEFAULT_CACHE_TTL),
		})
	}
}

/// Where the key version, and the `kid` naming it, come from.
#[derive(Clone)]
enum VersionSource {
	/// `keyVersion`; the `kid` is the configuration's.
	Pinned(u32),
	/// `publishedPair`: read at runtime.
	Published(Arc<PublishedPair>),
}

impl fmt::Debug for VersionSource {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Pinned(v) => write!(f, "Pinned({v})"),
			Self::Published(p) => f
				.debug_struct("Published")
				.field("path", &p.path)
				.field("refresh", &p.refresh)
				.finish_non_exhaustive(),
		}
	}
}

struct PublishedPair {
	path: String,
	refresh: Duration,
	/// The last pair read, and when.
	last: Mutex<Option<(SigningPair, Instant)>>,
}

/// The version that signs, and the `kid` naming it at the IdP (`None`: the
/// configuration's `clientAuth.kid`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct SigningPair {
	version: u32,
	kid: Option<String>,
}

impl VaultTransitSigner {
	/// Whether the `kid` comes from the engine with the version (`publishedPair`).
	pub(super) fn publishes_kid(&self) -> bool {
		matches!(self.version, VersionSource::Published(_))
	}
}

impl VaultTransitSigner {
	/// The JWS compact serialization of `header` and `claims` (base64url JSON),
	/// RSASSA-PKCS1-v1_5 with SHA-256. With a published pair, the header's `kid`
	/// is the pair's, read in the same step as the version that signs.
	pub(super) async fn sign_jws(
		&self,
		client: &PolicyClient,
		mut header: jsonwebtoken::Header,
		claims: String,
	) -> anyhow::Result<String> {
		let pair = self.pair(client).await?;
		if let Some(kid) = pair.kid {
			header.kid = Some(kid);
		}
		let input = format!(
			"{}.{claims}",
			URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?)
		);
		let signature = self.sign(client, pair.version, input.as_bytes()).await?;
		Ok(format!("{input}.{signature}"))
	}

	async fn pair(&self, client: &PolicyClient) -> anyhow::Result<SigningPair> {
		let published = match &self.version {
			VersionSource::Pinned(version) => {
				return Ok(SigningPair {
					version: *version,
					kid: None,
				});
			},
			VersionSource::Published(published) => published,
		};
		let last = published.last.lock().clone();
		if let Some((pair, read_at)) = &last
			&& read_at.elapsed() < published.refresh
		{
			return Ok(pair.clone());
		}
		match self.read_pair(client, &published.path).await {
			Ok(pair) => {
				if last.as_ref().map(|(p, _)| p) != Some(&pair) {
					info!(
						key = %self.key,
						version = pair.version,
						kid = pair.kid.as_deref().unwrap_or_default(),
						path = %published.path,
						"transit key: signing with the published version"
					);
				}
				*published.last.lock() = Some((pair.clone(), Instant::now()));
				Ok(pair)
			},
			// Keep the last good pair; it is read again on the next signature.
			Err(e) => match last {
				Some((pair, _)) => {
					warn!(
						key = %self.key,
						version = pair.version,
						path = %published.path,
						"could not read the published key version, keeping the last one read: {e:#}"
					);
					Ok(pair)
				},
				None => Err(e.context(format!(
					"no published key version for transit key {} yet",
					self.key
				))),
			},
		}
	}

	/// A KV v2 read of `{key_version, key_id}`.
	async fn read_pair(&self, client: &PolicyClient, path: &str) -> anyhow::Result<SigningPair> {
		let (status, resp) = self
			.authed(client, ::http::Method::GET, &format!("/v1/{path}"), None)
			.await?;
		if !status.is_success() {
			bail!("reading the published pair at {path} returned status {status}");
		}
		#[derive(Deserialize)]
		struct Kv {
			data: KvData,
		}
		#[derive(Deserialize)]
		struct KvData {
			data: Published,
		}
		#[derive(Deserialize)]
		struct Published {
			key_version: serde_json::Value,
			key_id: serde_json::Value,
		}
		let limit = http::response_buffer_limit(&resp);
		let kv: Kv = json::from_body_with_limit(resp.into_body(), limit)
			.await
			.with_context(|| {
				format!("the published pair at {path} is not a KV v2 secret with key_version and key_id")
			})?;
		let version = match &kv.data.data.key_version {
			serde_json::Value::Number(n) => n.as_u64(),
			serde_json::Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
				s.parse::<u64>().ok()
			},
			_ => None,
		}
		.and_then(|v| u32::try_from(v).ok())
		.filter(|v| *v > 0)
		.ok_or_else(|| anyhow!("the published pair at {path} has no key_version of 1 or more"))?;
		let kid = match &kv.data.data.key_id {
			serde_json::Value::String(s) if !s.trim().is_empty() => s.clone(),
			_ => bail!("the published pair at {path} has no key_id"),
		};
		Ok(SigningPair {
			version,
			kid: Some(kid),
		})
	}

	/// The base64url signature of `input` (a JWS signing input) by `version`. Any
	/// failure is returned, and nothing is signed any other way.
	async fn sign(
		&self,
		client: &PolicyClient,
		version: u32,
		input: &[u8],
	) -> anyhow::Result<String> {
		let body = json!({
			"input": STANDARD.encode(input),
			"key_version": version,
			"hash_algorithm": "sha2-256",
			"signature_algorithm": "pkcs1v15",
			"prehashed": false,
		});
		let (status, resp) = self
			.authed(
				client,
				::http::Method::POST,
				&format!("/v1/{}/sign/{}", self.mount, self.key),
				Some(body),
			)
			.await?;
		if !status.is_success() {
			bail!("transit sign returned status {status}");
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
			.context("transit sign response")?;
		let (signed_by, signature) = jws_signature(&sign.data.signature)?;
		if signed_by != version {
			bail!("transit signed with key version {signed_by}, not the requested {version}");
		}
		Ok(signature)
	}

	/// A call with the engine token. A token the engine refuses is replaced once.
	async fn authed(
		&self,
		client: &PolicyClient,
		method: ::http::Method,
		path: &str,
		body: Option<serde_json::Value>,
	) -> anyhow::Result<(StatusCode, ::http::Response<Body>)> {
		for attempt in 0..2 {
			let token = self.engine_token(client).await?;
			let (status, resp) = self
				.call(client, method.clone(), path, Some(&token), body.clone())
				.await?;
			if !matches!(status, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED) {
				return Ok((status, resp));
			}
			if attempt > 0 {
				bail!("transit refused a fresh engine token");
			}
			debug!(key = %self.key, "transit refused the engine token; logging in again");
			self.engine_token.invalidate(&ExchangeRequest::default());
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
				::http::Method::POST,
				&format!("/v1/auth/{}/login", self.login_path),
				None,
				Some(body),
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

	async fn call(
		&self,
		client: &PolicyClient,
		method: ::http::Method,
		path: &str,
		token: Option<&SecretString>,
		body: Option<serde_json::Value>,
	) -> anyhow::Result<(StatusCode, ::http::Response<Body>)> {
		let mut builder = ::http::Request::builder()
			.method(method)
			.uri(path)
			.header(ACCEPT, "application/json");
		if body.is_some() {
			builder = builder.header(CONTENT_TYPE, "application/json");
		}
		if let Some(namespace) = &self.namespace {
			builder = builder.header("x-vault-namespace", namespace);
		}
		if let Some(token) = token {
			builder = builder.header("x-vault-token", token.expose_secret());
		}
		let mut req = match body {
			Some(body) => builder.body(Body::from(serde_json::to_vec(&body)?))?,
			None => builder.body(Body::empty())?,
		};
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
