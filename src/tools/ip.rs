///
/// This module contains tools for analyzing IP addresses.
///
use crate::cortex;
use rmcp::{
    handler::server::tool::Parameters,
    model::*,
    schemars, ErrorData,
};
use std::net::IpAddr;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AnalyzeIpParams {
    #[schemars(description = "The IP address to analyze.")]
    pub ip: String,
    #[schemars(
        description = "Optional: The name of the AbuseIPDB analyzer instance in Cortex. Defaults to 'AbuseIPDB_1_0'."
    )]
    pub analyzer_name: Option<String>,
    #[schemars(description = "Optional: Maximum number of retries to wait for the analyzer job to complete. Defaults to 5.")]
    pub max_retries: Option<usize>,
}

pub async fn analyze_ip_with_abuseipdb(
    server: &crate::CortexToolsServer,
    Parameters(params): Parameters<AnalyzeIpParams>,
) -> Result<CallToolResult, ErrorData> {
    let ip_to_analyze = params.ip;
    
    // Validate IP address
    if let Err(e) = validate_ip(&ip_to_analyze) {
        return Ok(CallToolResult::error(vec![Content::text(format!("Invalid IP: {}", e))]));
    }
    let analyzer_name_to_run = params
        .analyzer_name
        .unwrap_or_else(|| "AbuseIPDB_1_0".to_string());
    
    let job_create_request = cortex_client::models::JobCreateRequest {
        data: Some(ip_to_analyze.clone()),
        data_type: Some("ip".to_string()),
        tlp: Some(2),
        pap: Some(2),
        message: Some(Some(format!(
            "MCP Cortex Server: Analyzing IP {} with {}",
            ip_to_analyze, analyzer_name_to_run
        ))),
        parameters: None,
        label: Some(Some(format!("mcp_ip_analysis_{}", ip_to_analyze))),
        force: Some(false),
        attributes: None,
    };

    cortex::run_analyzer_and_get_report(
        &server.cortex_config,
        &analyzer_name_to_run,
        job_create_request,
        &ip_to_analyze,
        params.max_retries.unwrap_or(5),
    )
    .await
}

// --- Utility Functions ---

/// Validates an IP address to ensure it's properly formatted
fn validate_ip(ip: &str) -> Result<(), String> {
    if ip.trim().is_empty() {
        return Err("IP address cannot be empty".to_string());
    }
    
    // Parse IP address to validate format
    ip.parse::<IpAddr>().map_err(|_| "Invalid IP address format".to_string())?;
    
    // Check for private/loopback addresses that shouldn't be analyzed
    let parsed_ip = ip.parse::<IpAddr>().unwrap();
    match parsed_ip {
        IpAddr::V4(ipv4) => {
            if ipv4.is_loopback() || ipv4.is_private() || ipv4.is_link_local() {
                return Err("Private, loopback, or link-local IP addresses cannot be analyzed".to_string());
            }
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_loopback() || ipv6.is_multicast() {
                return Err("Loopback or multicast IPv6 addresses cannot be analyzed".to_string());
            }
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ip_valid() {
        assert!(validate_ip("8.8.8.8").is_ok());
        assert!(validate_ip("1.1.1.1").is_ok());
        assert!(validate_ip("2001:4860:4860::8888").is_ok());
    }

    #[test]
    fn test_validate_ip_empty() {
        assert!(validate_ip("").is_err());
        assert!(validate_ip("   ").is_err());
    }

    #[test]
    fn test_validate_ip_invalid_format() {
        assert!(validate_ip("256.256.256.256").is_err());
        assert!(validate_ip("192.168.1").is_err());
        assert!(validate_ip("not.an.ip.address").is_err());
        assert!(validate_ip("192.168.1.1.1").is_err());
    }

    #[test]
    fn test_validate_ip_private_addresses() {
        assert!(validate_ip("192.168.1.1").is_err());
        assert!(validate_ip("10.0.0.1").is_err());
        assert!(validate_ip("172.16.0.1").is_err());
        assert!(validate_ip("127.0.0.1").is_err());
        assert!(validate_ip("169.254.1.1").is_err());
    }

    #[test]
    fn test_validate_ip_ipv6_special() {
        assert!(validate_ip("::1").is_err()); // loopback
        assert!(validate_ip("ff02::1").is_err()); // multicast
    }
}
