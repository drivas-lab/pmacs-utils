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
#[derive(Debug, Clone)]
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
    debug!("Prelogin response: {}", body);

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

/// Step 2: Authenticate with username/password
///
/// For DUO MFA, use passcode="push" to trigger a push notification
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
    info!("Logging in as {} (passcode: {})", username, passcode.unwrap_or("none"));

    let client = Client::builder()
        .danger_accept_invalid_certs(false)
        .build()?;

    let url = format!("https://{}/ssl-vpn/login.esp", gateway);

    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());

    let mut params: HashMap<&str, String> = [
        ("user", username.to_string()),
        ("passwd", password.to_string()),
        ("computer", hostname),
        ("os-version", "Windows".to_string()),
    ]
    .iter()
    .cloned()
    .collect();

    if let Some(code) = passcode {
        params.insert("passcode", code.to_string());
    }

    let response = client
        .post(&url)
        .header("User-Agent", "PAN GlobalProtect")
        .form(&params)
        .send()
        .await?;

    let body = response.text().await?;
    debug!("Login response: {}", body);

    let jnlp: JnlpXml = quick_xml::de::from_str(&body)
        .map_err(|e| AuthError::AuthFailed(format!("Invalid login response: {}", e)))?;

    // Parse the JNLP arguments which come as key-value pairs
    let args = &jnlp.application_desc.argument;
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
        domain: domain.unwrap_or_else(|| "".to_string()),
        portal: portal.unwrap_or_else(|| gateway.to_string()),
        gateway_address: gateway_address.unwrap_or_else(|| gateway.to_string()),
    })
}

/// Step 3: Get tunnel configuration
///
/// # Arguments
/// * `gateway` - Gateway hostname
/// * `auth_cookie` - Authentication cookie from login
/// * `preferred_ip` - Optional preferred IP address
///
/// # Returns
/// Tunnel configuration with IP, DNS, MTU settings
pub async fn getconfig(
    gateway: &str,
    auth_cookie: &str,
    preferred_ip: Option<IpAddr>,
) -> Result<TunnelConfig, AuthError> {
    info!("Getting tunnel configuration");

    let client = Client::builder()
        .danger_accept_invalid_certs(false)
        .build()?;

    let url = format!("https://{}/ssl-vpn/getconfig.esp", gateway);

    let preferred = preferred_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "0.0.0.0".to_string());

    let params = [
        ("user", ""),
        ("portal", gateway),
        ("authcookie", auth_cookie),
        ("preferred-ip", &preferred),
        ("client-type", "1"),
        ("os-version", "Windows"),
        ("app-version", "4.1.0"),
    ];

    let response = client
        .post(&url)
        .header("User-Agent", "PAN GlobalProtect")
        .form(&params)
        .send()
        .await?;

    let body = response.text().await?;
    debug!("Getconfig response: {}", body);

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

    let mtu = policy
        .mtu
        .as_ref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1400);

    let dns_servers = policy
        .dns
        .as_ref()
        .map(|dns| {
            dns.member
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect()
        })
        .unwrap_or_default();

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
}
