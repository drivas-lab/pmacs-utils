//! GlobalProtect authentication module
//!
//! Implements the three-step auth flow:
//! 1. prelogin - Check auth method
//! 2. login - Authenticate with credentials (supports DUO push)
//! 3. getconfig - Get tunnel configuration

use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use thiserror::Error;
use tracing::{debug, info};

/// Authentication errors
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("XML parsing failed: {0}")]
    XmlError(#[from] quick_xml::DeError),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid response format")]
    InvalidResponse,
}

/// Authentication method
#[derive(Debug, Clone, PartialEq)]
pub enum AuthMethod {
    Password,
    Saml,
}

/// Pre-login response
#[derive(Debug, Clone)]
pub struct PreloginResponse {
    pub auth_method: AuthMethod,
    pub label_username: String,
    pub label_password: String,
    pub saml_request: Option<String>,
}

/// Login response containing the authentication cookie
#[derive(Debug, Clone)]
pub struct LoginResponse {
    pub auth_cookie: String,
    pub username: String,
    pub domain: String,
    pub portal: String,
    pub gateway_address: String,
}

/// Tunnel configuration from getconfig
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TunnelConfig {
    pub mtu: u16,
    pub internal_ip: IpAddr,
    pub internal_ip6: Option<std::net::Ipv6Addr>,
    pub dns_servers: Vec<IpAddr>,
    pub timeout_seconds: u64,
}

// XML deserialization structures for prelogin
#[derive(Debug, Deserialize)]
#[serde(rename = "prelogin-response")]
struct PreloginXml {
    status: String,
    #[serde(rename = "username-label", default)]
    username_label: Option<String>,
    #[serde(rename = "password-label", default)]
    password_label: Option<String>,
    #[serde(rename = "saml-auth-method", default)]
    saml_auth_method: Option<String>,
}

// XML deserialization structures for login
#[derive(Debug, Deserialize)]
struct JnlpXml {
    #[serde(rename = "application-desc")]
    application_desc: ApplicationDesc,
}

#[derive(Debug, Deserialize)]
struct ApplicationDesc {
    argument: Vec<String>,
}

// XML deserialization structures for getconfig
#[derive(Debug, Deserialize)]
#[serde(rename = "policy")]
#[allow(dead_code)]
struct PolicyXml {
    #[serde(rename = "gateways")]
    gateways: Option<Gateways>,
    #[serde(rename = "ip-address", default)]
    ip_address: Option<String>,
    #[serde(rename = "ipv6-address", default)]
    ipv6_address: Option<String>,
    #[serde(rename = "mtu", default)]
    mtu: Option<String>,
    #[serde(rename = "dns", default)]
    dns: Option<Dns>,
    #[serde(rename = "timeout", default)]
    timeout: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Gateways {
    #[serde(rename = "external")]
    external: External,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct External {
    list: String,
}

#[derive(Debug, Deserialize)]
struct Dns {
    member: Vec<String>,
}

/// Step 1: Check what auth method is required
///
/// # Arguments
/// * `gateway` - Gateway hostname (e.g., "psomvpn.uphs.upenn.edu")
///
/// # Returns
/// Pre-login response with authentication method details
pub async fn prelogin(gateway: &str) -> Result<PreloginResponse, AuthError> {
    info!("Sending prelogin request to {}", gateway);

    let client = Client::builder()
        .danger_accept_invalid_certs(false)
        .build()?;

    let url = format!("https://{}/ssl-vpn/prelogin.esp", gateway);
    let params = [
        ("tmp", "tmp"),
        ("clientVer", "4100"),
        ("clientos", "Windows"),
    ];

    let response = client
        .post(&url)
        .header("User-Agent", "PAN GlobalProtect")
        .form(&params)
        .send()
        .await?;

    let body = response.text().await?;
    debug!("Prelogin response received ({} bytes)", body.len());

    let prelogin: PreloginXml = quick_xml::de::from_str(&body)?;

    if prelogin.status != "Success" {
        return Err(AuthError::AuthFailed(format!(
            "Prelogin failed: {}",
            prelogin.status
        )));
    }

    let auth_method = if prelogin.saml_auth_method.is_some() {
        AuthMethod::Saml
    } else {
        AuthMethod::Password
    };

    Ok(PreloginResponse {
        auth_method,
        label_username: prelogin.username_label.unwrap_or_else(|| "Username".to_string()),
        label_password: prelogin.password_label.unwrap_or_else(|| "Password".to_string()),
        saml_request: prelogin.saml_auth_method,
    })
}

/// Challenge response from first login step (MFA required)
#[derive(Debug)]
struct ChallengeResponse {
    input_str: String,
    message: String,
}

/// Parse HTML challenge response
/// Format: var respStatus = "Challenge"; var respMsg = "..."; thisForm.inputStr.value = "...";
fn parse_challenge(body: &str) -> Option<ChallengeResponse> {
    // Check if this is a challenge response
    if !body.contains("respStatus = \"Challenge\"") {
        return None;
    }

    // Extract inputStr value using regex-like parsing
    let input_str = body
        .find("inputStr.value = \"")
        .and_then(|start| {
            let rest = &body[start + 18..];
            rest.find('"').map(|end| rest[..end].to_string())
        })?;

    // Extract message
    let message = body
        .find("respMsg = \"")
        .and_then(|start| {
            let rest = &body[start + 11..];
            rest.find('"').map(|end| rest[..end].to_string())
        })
        .unwrap_or_else(|| "Enter passcode".to_string());

    Some(ChallengeResponse { input_str, message })
}

/// Parse JNLP login response
/// Handles both labeled format: (auth-cookie), value, (portal), value, ...
/// And positional format: empty, cookie, persistent-cookie, gateway, user, profile, vsys, domain, ...
fn parse_jnlp_response(body: &str, username: &str, gateway: &str) -> Result<LoginResponse, AuthError> {
    let jnlp: JnlpXml = quick_xml::de::from_str(body)
        .map_err(|e| AuthError::AuthFailed(format!("Invalid login response: {}", e)))?;

    let args = &jnlp.application_desc.argument;

    if args.is_empty() {
        return Err(AuthError::InvalidResponse);
    }

    // Check if this is labeled format (first non-empty arg starts with "(")
    let is_labeled = args.iter().any(|a| a.starts_with('('));

    if is_labeled {
        // Labeled format: key-value pairs like (auth-cookie), value
        let mut auth_cookie = None;
        let mut portal = None;
        let mut domain = None;
        let mut gateway_address = None;

        let mut i = 0;
        while i < args.len() {
            let key = &args[i];
            if i + 1 < args.len() {
                let value = &args[i + 1];
                match key.as_str() {
                    "(auth-cookie)" => auth_cookie = Some(value.clone()),
                    "(portal)" => portal = Some(value.clone()),
                    "(domain)" => domain = Some(value.clone()),
                    "(gateway-address)" => gateway_address = Some(value.clone()),
                    _ => {}
                }
            }
            i += 2;
        }

        Ok(LoginResponse {
            auth_cookie: auth_cookie.ok_or_else(|| AuthError::MissingField("auth-cookie".to_string()))?,
            username: username.to_string(),
            domain: domain.unwrap_or_default(),
            portal: portal.unwrap_or_else(|| gateway.to_string()),
            gateway_address: gateway_address.unwrap_or_else(|| gateway.to_string()),
        })
    } else {
        // Positional format from PMACS-style servers:
        // [0]: empty or user
        // [1]: auth-cookie (32 hex chars)
        // [2]: persistent-cookie (40 hex chars, anti-MITM)
        // [3]: gateway name
        // [4]: username
        // [5]: auth profile
        // [6]: vsys
        // [7]: domain
        debug!("Parsing positional JNLP format with {} arguments", args.len());

        // Auth cookie is at index 1 (32 hex chars)
        let auth_cookie = args.get(1)
            .filter(|s| !s.is_empty() && s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()))
            .cloned()
            .ok_or_else(|| AuthError::MissingField("auth-cookie at index 1".to_string()))?;

        // Gateway at index 3
        let gateway_name = args.get(3)
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or_else(|| gateway.to_string());

        // Username at index 4 (or use provided)
        let user = args.get(4)
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or_else(|| username.to_string());

        // Domain at index 7
        let domain = args.get(7)
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or_default();

        Ok(LoginResponse {
            auth_cookie,
            username: user,
            domain,
            portal: gateway.to_string(),
            gateway_address: gateway_name,
        })
    }
}

/// Step 2: Authenticate with username/password
///
/// For DUO MFA, use passcode="push" to trigger a push notification.
/// This handles the two-step challenge flow:
/// 1. First request with password → returns Challenge with token
/// 2. Second request with token + passcode → returns auth cookie
///
/// # Arguments
/// * `gateway` - Gateway hostname
/// * `username` - User's username
/// * `password` - User's password
/// * `passcode` - Optional passcode (use "push" for DUO push notification)
///
/// # Returns
/// Login response with authentication cookie
pub async fn login(
    gateway: &str,
    username: &str,
    password: &str,
    passcode: Option<&str>,
) -> Result<LoginResponse, AuthError> {
    info!("Logging in as {} (passcode: {})", username, if passcode.is_some() { "provided" } else { "none" });

    let client = Client::builder()
        .danger_accept_invalid_certs(false)
        .cookie_store(true)  // Maintain session cookies for MFA flow
        .build()?;

    let url = format!("https://{}/ssl-vpn/login.esp", gateway);

    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());

    // First request: send credentials
    // Required params per GP protocol doc: user, passwd, ok=Login, jnlpReady, direct, server, etc.
    let params: HashMap<&str, String> = [
        ("user", username.to_string()),
        ("passwd", password.to_string()),
        ("jnlpReady", "jnlpReady".to_string()),  // Required!
        ("ok", "Login".to_string()),              // Required!
        ("direct", "yes".to_string()),            // Required!
        ("prot", "https:".to_string()),
        ("server", gateway.to_string()),
        ("computer", hostname.clone()),
        ("os-version", "Microsoft Windows 10 Pro".to_string()),
        ("clientos", "Windows".to_string()),
        ("clientVer", "4100".to_string()),
        ("ipv6-support", "yes".to_string()),
    ]
    .iter()
    .cloned()
    .collect();

    let response = client
        .post(&url)
        .header("User-Agent", "PAN GlobalProtect")
        .form(&params)
        .send()
        .await?;

    let body = response.text().await?;
    debug!("Login response received ({} bytes)", body.len());

    // Check if this is a challenge response (MFA required)
    if let Some(challenge) = parse_challenge(&body) {
        info!("MFA challenge received: {}", challenge.message);

        // Second request: send challenge token with passcode in passwd field
        // For DUO push, the server will block until the user approves
        let passcode = passcode.unwrap_or("push");
        info!("Sending MFA response with passcode: {} (waiting for approval...)", passcode);

        let challenge_params: HashMap<&str, String> = [
            ("user", username.to_string()),
            ("passwd", passcode.to_string()),  // Passcode goes in passwd field for MFA step
            ("inputStr", challenge.input_str),
            ("jnlpReady", "jnlpReady".to_string()),  // Required!
            ("ok", "Login".to_string()),              // Required!
            ("direct", "yes".to_string()),            // Required!
            ("prot", "https:".to_string()),
            ("server", gateway.to_string()),
            ("computer", hostname.clone()),
            ("os-version", "Microsoft Windows 10 Pro".to_string()),
            ("clientos", "Windows".to_string()),
            ("clientVer", "4100".to_string()),
            ("ipv6-support", "yes".to_string()),
        ]
        .iter()
        .cloned()
        .collect();

        let challenge_response = client
            .post(&url)
            .header("User-Agent", "PAN GlobalProtect")
            .form(&challenge_params)
            .send()
            .await?;

        debug!("MFA response status: {}", challenge_response.status());

        let challenge_body = challenge_response.text().await?;
        debug!("MFA response received ({} bytes)", challenge_body.len());

        // Check for error response
        if challenge_body.contains("respStatus = \"Error\"") {
            // Extract error message
            let msg = challenge_body
                .find("respMsg = \"")
                .and_then(|start| {
                    let rest = &challenge_body[start + 11..];
                    rest.find('"').map(|end| rest[..end].to_string())
                })
                .unwrap_or_else(|| "Unknown error".to_string());
            return Err(AuthError::AuthFailed(format!("MFA failed: {}", msg)));
        }

        // Check for another challenge (wrong passcode, etc.)
        if let Some(retry_challenge) = parse_challenge(&challenge_body) {
            return Err(AuthError::AuthFailed(format!(
                "MFA failed: {}",
                retry_challenge.message
            )));
        }

        // If empty response with 200 OK, MFA succeeded but we need to retry login
        // to get the actual JNLP response
        if challenge_body.is_empty() {
            info!("MFA accepted, completing login...");

            // Retry login with original credentials - session is now MFA-validated
            let retry_params: HashMap<&str, String> = [
                ("user", username.to_string()),
                ("passwd", password.to_string()),
                ("jnlpReady", "jnlpReady".to_string()),
                ("ok", "Login".to_string()),
                ("direct", "yes".to_string()),
                ("prot", "https:".to_string()),
                ("server", gateway.to_string()),
                ("computer", hostname),
                ("os-version", "Microsoft Windows 10 Pro".to_string()),
                ("clientos", "Windows".to_string()),
                ("clientVer", "4100".to_string()),
                ("ipv6-support", "yes".to_string()),
            ]
            .iter()
            .cloned()
            .collect();

            let retry_response = client
                .post(&url)
                .header("User-Agent", "PAN GlobalProtect")
                .form(&retry_params)
                .send()
                .await?;

            debug!("Retry login status: {}", retry_response.status());

            let retry_body = retry_response.text().await?;
            debug!("Retry login body: {}", retry_body);

            return parse_jnlp_response(&retry_body, username, gateway);
        }

        return parse_jnlp_response(&challenge_body, username, gateway);
    }

    // No challenge - parse as JNLP directly
    parse_jnlp_response(&body, username, gateway)
}

/// Helper function to parse MTU from policy XML
/// Server may return MTU 0 meaning "use default" - use 1400 as safe default
fn parse_mtu(policy: &PolicyXml) -> u16 {
    policy
        .mtu
        .as_ref()
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|&m| m > 0)
        .unwrap_or(1400)
}

/// Helper function to parse DNS servers from policy XML
fn parse_dns_servers(policy: &PolicyXml) -> Vec<IpAddr> {
    policy
        .dns
        .as_ref()
        .map(|dns| {
            dns.member
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Shared implementation for getting tunnel configuration
async fn getconfig_impl(
    gateway: &str,
    username: &str,
    auth_cookie: &str,
    portal: &str,
    domain: &str,
    preferred_ip: Option<IpAddr>,
) -> Result<TunnelConfig, AuthError> {
    let client = Client::builder()
        .danger_accept_invalid_certs(false)
        .build()?;

    let url = format!("https://{}/ssl-vpn/getconfig.esp", gateway);

    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());

    let preferred = preferred_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "0.0.0.0".to_string());

    // Full parameter set per GP protocol doc
    let params = [
        ("user", username),
        ("portal", portal),
        ("domain", domain),
        ("authcookie", auth_cookie),
        ("preferred-ip", preferred.as_str()),
        ("clientos", "Windows"),
        ("os-version", "Microsoft Windows 10 Pro"),
        ("app-version", "4.1.0-10"),
        ("protocol-version", "p1"),
        ("client-type", "1"),
        ("enc-algo", "aes-256-gcm,aes-128-gcm,aes-128-cbc"),
        ("hmac-algo", "sha1"),
        ("computer", hostname.as_str()),
    ];

    let response = client
        .post(&url)
        .header("User-Agent", "PAN GlobalProtect")
        .form(&params)
        .send()
        .await?;

    let body = response.text().await?;
    debug!("Getconfig response received ({} bytes)", body.len());

    let policy: PolicyXml = quick_xml::de::from_str(&body)
        .map_err(|e| AuthError::AuthFailed(format!("Invalid getconfig response: {}", e)))?;

    let internal_ip: IpAddr = policy
        .ip_address
        .as_ref()
        .ok_or_else(|| AuthError::MissingField("ip-address".to_string()))?
        .parse()
        .map_err(|_| AuthError::InvalidResponse)?;

    let internal_ip6 = policy
        .ipv6_address
        .as_ref()
        .and_then(|s| s.parse().ok());

    let mtu = parse_mtu(&policy);
    let dns_servers = parse_dns_servers(&policy);

    let timeout_seconds = policy
        .timeout
        .as_ref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600);

    Ok(TunnelConfig {
        mtu,
        internal_ip,
        internal_ip6,
        dns_servers,
        timeout_seconds,
    })
}

/// Step 3: Get tunnel configuration
///
/// # Arguments
/// * `gateway` - Gateway hostname
/// * `login` - Login response containing auth cookie and user info
/// * `preferred_ip` - Optional preferred IP address
///
/// # Returns
/// Tunnel configuration with IP, DNS, MTU settings
pub async fn getconfig(
    gateway: &str,
    login: &LoginResponse,
    preferred_ip: Option<IpAddr>,
) -> Result<TunnelConfig, AuthError> {
    info!("Getting tunnel configuration");

    getconfig_impl(
        gateway,
        &login.username,
        &login.auth_cookie,
        &login.portal,
        &login.domain,
        preferred_ip,
    )
    .await
}

/// Get tunnel configuration using raw auth cookie (for daemon mode)
/// This is used when the parent process has already done auth and saved the cookie
pub async fn getconfig_with_cookie(
    gateway: &str,
    username: &str,
    auth_cookie: &str,
    portal: &str,
    domain: &str,
    preferred_ip: Option<IpAddr>,
) -> Result<TunnelConfig, AuthError> {
    info!("Getting tunnel configuration (daemon mode)");

    getconfig_impl(
        gateway,
        username,
        auth_cookie,
        portal,
        domain,
        preferred_ip,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_prelogin_password() {
        let xml = r#"
            <prelogin-response>
                <status>Success</status>
                <username-label>Username</username-label>
                <password-label>Password</password-label>
            </prelogin-response>
        "#;

        let prelogin: PreloginXml = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(prelogin.status, "Success");
        assert_eq!(prelogin.username_label, Some("Username".to_string()));
        assert_eq!(prelogin.password_label, Some("Password".to_string()));
        assert_eq!(prelogin.saml_auth_method, None);
    }

    #[test]
    fn test_parse_login_response() {
        let xml = r#"
            <jnlp>
                <application-desc>
                    <argument>(auth-cookie)</argument>
                    <argument>test-cookie-value</argument>
                    <argument>(portal)</argument>
                    <argument>test-portal</argument>
                    <argument>(domain)</argument>
                    <argument>test-domain</argument>
                </application-desc>
            </jnlp>
        "#;

        let jnlp: JnlpXml = quick_xml::de::from_str(xml).unwrap();
        let args = &jnlp.application_desc.argument;

        // Parse key-value pairs
        let mut auth_cookie = None;
        let mut portal = None;
        let mut i = 0;
        while i < args.len() {
            if i + 1 < args.len() {
                match args[i].as_str() {
                    "(auth-cookie)" => auth_cookie = Some(args[i + 1].clone()),
                    "(portal)" => portal = Some(args[i + 1].clone()),
                    _ => {}
                }
            }
            i += 2;
        }

        assert_eq!(auth_cookie, Some("test-cookie-value".to_string()));
        assert_eq!(portal, Some("test-portal".to_string()));
    }

    #[test]
    fn test_parse_positional_jnlp_response() {
        // PMACS-style positional format (no labels)
        let xml = r#"<?xml version="1.0" encoding="UTF-8" ?>
<jnlp>
<application-desc>
<argument></argument>
<argument>ec85fe94925569dbaf7f38bfe736da90</argument>
<argument>651e643201afcb354d58b58d9412f3a168db1fa4</argument>
<argument>psom_admin_vpn_gateway-N</argument>
<argument>yjk</argument>
<argument>PSOM_DUO_profile_GP</argument>
<argument>vsys1</argument>
<argument>pmacs</argument>
<argument></argument>
</application-desc>
</jnlp>"#;

        let result = parse_jnlp_response(xml, "yjk", "psomvpn.uphs.upenn.edu");
        assert!(result.is_ok(), "Failed to parse: {:?}", result);
        let login = result.unwrap();
        assert_eq!(login.auth_cookie, "ec85fe94925569dbaf7f38bfe736da90");
        assert_eq!(login.username, "yjk");
        assert_eq!(login.domain, "pmacs");
        assert_eq!(login.gateway_address, "psom_admin_vpn_gateway-N");
    }

    #[test]
    fn test_parse_getconfig_response() {
        let xml = r#"
            <policy>
                <ip-address>10.0.1.100</ip-address>
                <mtu>1400</mtu>
                <dns>
                    <member>8.8.8.8</member>
                    <member>8.8.4.4</member>
                </dns>
                <timeout>3600</timeout>
            </policy>
        "#;

        let policy: PolicyXml = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(policy.ip_address, Some("10.0.1.100".to_string()));
        assert_eq!(policy.mtu, Some("1400".to_string()));
        assert!(policy.dns.is_some());
        assert_eq!(policy.dns.unwrap().member.len(), 2);
    }

    #[test]
    fn test_parse_challenge_response() {
        let html = r#"<html>
  <head></head>
  <body>
  var respStatus = "Challenge";
  var respMsg = "Enter passcode:";
  thisForm.inputStr.value = "691e86260039364e";
</body>
</html>"#;

        let challenge = parse_challenge(html);
        assert!(challenge.is_some());
        let challenge = challenge.unwrap();
        assert_eq!(challenge.input_str, "691e86260039364e");
        assert_eq!(challenge.message, "Enter passcode:");
    }

    #[test]
    fn test_parse_non_challenge_response() {
        let xml = r#"<jnlp><application-desc></application-desc></jnlp>"#;
        let challenge = parse_challenge(xml);
        assert!(challenge.is_none());
    }
}
