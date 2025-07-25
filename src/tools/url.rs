///
/// This module contains tools for analyzing URLs.
///
use crate::cortex;
use rmcp::{
    handler::server::tool::Parameters,
    model::*,
    schemars, ErrorData,
};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ScanUrlWithVirusTotalParams {
    #[schemars(description = "The URL to scan.")]
    pub url: String,
    #[schemars(
        description = "Optional: The name of the VirusTotal_Scan analyzer instance in Cortex. Defaults to 'VirusTotal_Scan_3_1'."
    )]
    pub analyzer_name: Option<String>,
    #[schemars(description = "Optional: Maximum number of retries to wait for the analyzer job to complete. Defaults to 5.")]
    pub max_retries: Option<usize>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AnalyzeUrlWithUrlscanIoParams {
    #[schemars(description = "The URL to scan.")]
    pub url: String,
    #[schemars(
        description = "Optional: The name of the Urlscan_io_Scan analyzer instance in Cortex. Defaults to 'Urlscan_io_Scan_0_1_0'."
    )]
    pub analyzer_name: Option<String>,
    #[schemars(description = "Optional: Maximum number of retries to wait for the analyzer job to complete. Defaults to 5.")]
    pub max_retries: Option<usize>,
}

pub async fn scan_url_with_virustotal(
    server: &crate::CortexToolsServer,
    Parameters(params): Parameters<ScanUrlWithVirusTotalParams>,
) -> Result<CallToolResult, ErrorData> {
    let url_to_scan = params.url;
    
    // Validate URL
    if let Err(e) = validate_url(&url_to_scan) {
        return Ok(CallToolResult::error(vec![Content::text(format!("Invalid URL: {}", e))]));
    }
    let analyzer_name_to_run = params
        .analyzer_name
        .unwrap_or_else(|| "VirusTotal_Scan_3_1".to_string());

    let job_create_request = cortex_client::models::JobCreateRequest {
        data: Some(url_to_scan.clone()),
        data_type: Some("url".to_string()),
        tlp: Some(2),
        pap: Some(2),
        message: Some(Some(format!(
            "MCP Cortex Server: Scanning URL {} with {}",
            url_to_scan, analyzer_name_to_run
        ))),
        parameters: None,
        label: Some(Some(format!("mcp_url_scan_{}", url_to_scan))),
        force: Some(false),
        attributes: None,
    };

    cortex::run_analyzer_and_get_report(
        &server.cortex_config,
        &analyzer_name_to_run,
        job_create_request,
        &url_to_scan,
        params.max_retries.unwrap_or(5),
    )
    .await
}

pub async fn analyze_url_with_urlscan_io(
    server: &crate::CortexToolsServer,
    Parameters(params): Parameters<AnalyzeUrlWithUrlscanIoParams>,
) -> Result<CallToolResult, ErrorData> {
    let url_to_analyze = params.url;
    
    // Validate URL
    if let Err(e) = validate_url(&url_to_analyze) {
        return Ok(CallToolResult::error(vec![Content::text(format!("Invalid URL: {}", e))]));
    }
    let analyzer_name_to_run = params
        .analyzer_name
        .unwrap_or_else(|| "Urlscan_io_Scan_0_1_0".to_string());

    let job_create_request = cortex_client::models::JobCreateRequest {
        data: Some(url_to_analyze.clone()),
        data_type: Some("url".to_string()),
        tlp: Some(2),
        pap: Some(2),
        message: Some(Some(format!(
            "MCP Cortex Server: Analyzing URL {} with {}",
            url_to_analyze, analyzer_name_to_run
        ))),
        parameters: None,
        label: Some(Some(format!("mcp_urlscanio_analysis_{}", url_to_analyze))),
        force: Some(false),
        attributes: None,
    };

    cortex::run_analyzer_and_get_report(
        &server.cortex_config,
        &analyzer_name_to_run,
        job_create_request,
        &url_to_analyze,
        params.max_retries.unwrap_or(5),
    )
    .await
}

// --- Utility Functions ---

/// Validates a URL to ensure it's properly formatted and uses http/https
fn validate_url(url: &str) -> Result<(), String> {
    if url.trim().is_empty() {
        return Err("URL cannot be empty".to_string());
    }
    
    // Basic URL validation
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("URL must start with http:// or https://".to_string());
    }
    
    // Check for potentially malicious patterns
    if url.contains("javascript:") || url.contains("data:") || url.contains("file:") {
        return Err("URL scheme not allowed".to_string());
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_url_valid() {
        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("http://example.com").is_ok());
        assert!(validate_url("https://example.com/path").is_ok());
        assert!(validate_url("http://example.com:8080/path?query=value").is_ok());
    }

    #[test]
    fn test_validate_url_empty() {
        assert!(validate_url("").is_err());
        assert!(validate_url("   ").is_err());
    }

    #[test]
    fn test_validate_url_invalid_scheme() {
        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("example.com").is_err());
        assert!(validate_url("javascript:alert('xss')").is_err());
        assert!(validate_url("data:text/html,<script>alert('xss')</script>").is_err());
        assert!(validate_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_validate_url_malicious_patterns() {
        assert!(validate_url("https://example.com/javascript:alert('xss')").is_err());
        assert!(validate_url("https://example.com/data:text/html").is_err());
        assert!(validate_url("https://example.com/file:///etc/passwd").is_err());
    }
}