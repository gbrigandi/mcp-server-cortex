///
/// This module contains tools for analyzing file hashes.
///
use crate::cortex;
use rmcp::{
    handler::server::tool::Parameters,
    model::*,
    schemars, ErrorData,
};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ScanHashWithVirusTotalParams {
    #[schemars(description = "The hash to scan.")]
    pub hash: String,
    #[schemars(
        description = "Optional: The name of the VirusTotal_GetReport analyzer instance in Cortex. Defaults to 'VirusTotal_GetReport_3_1'."
    )]
    pub analyzer_name: Option<String>,
    #[schemars(description = "Optional: Maximum number of retries to wait for the analyzer job to complete. Defaults to 5.")]
    pub max_retries: Option<usize>,
}

pub async fn scan_hash_with_virustotal(
    server: &crate::CortexToolsServer,
    Parameters(params): Parameters<ScanHashWithVirusTotalParams>,
) -> Result<CallToolResult, ErrorData> {
    let hash_to_scan = params.hash;
    
    // Validate hash
    if let Err(e) = validate_hash(&hash_to_scan) {
        return Ok(CallToolResult::error(vec![Content::text(format!("Invalid hash: {}", e))]));
    }
    let analyzer_name_to_run = params
        .analyzer_name
        .unwrap_or_else(|| "VirusTotal_GetReport_3_1".to_string());

    let job_create_request = cortex_client::models::JobCreateRequest {
        data: Some(hash_to_scan.clone()),
        data_type: Some("hash".to_string()),
        tlp: Some(2),
        pap: Some(2),
        message: Some(Some(format!(
            "MCP Cortex Server: Scanning hash {} with {}",
            hash_to_scan, analyzer_name_to_run
        ))),
        parameters: None,
        label: Some(Some(format!("mcp_hash_scan_{}", hash_to_scan))),
        force: Some(false),
        attributes: None,
    };

    cortex::run_analyzer_and_get_report(
        &server.cortex_config,
        &analyzer_name_to_run,
        job_create_request,
        &hash_to_scan,
        params.max_retries.unwrap_or(5),
    )
    .await
}

// --- Utility Functions ---

/// Validates a hash to ensure it's properly formatted
fn validate_hash(hash: &str) -> Result<(), String> {
    if hash.trim().is_empty() {
        return Err("Hash cannot be empty".to_string());
    }
    
    let clean_hash = hash.trim();
    
    // Check for valid hex characters
    if !clean_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Hash must contain only hexadecimal characters".to_string());
    }
    
    // Check for common hash lengths (MD5: 32, SHA1: 40, SHA256: 64, SHA512: 128)
    match clean_hash.len() {
        32 | 40 | 64 | 128 => Ok(()),
        _ => Err("Hash length must be 32 (MD5), 40 (SHA1), 64 (SHA256), or 128 (SHA512) characters".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_hash_valid() {
        // MD5 (32 characters)
        assert!(validate_hash("d41d8cd98f00b204e9800998ecf8427e").is_ok());
        // SHA1 (40 characters)
        assert!(validate_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709").is_ok());
        // SHA256 (64 characters)
        assert!(validate_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").is_ok());
        // SHA512 (128 characters)
        assert!(validate_hash("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e").is_ok());
    }

    #[test]
    fn test_validate_hash_empty() {
        assert!(validate_hash("").is_err());
        assert!(validate_hash("   ").is_err());
    }

    #[test]
    fn test_validate_hash_invalid_length() {
        assert!(validate_hash("d41d8cd98f00b204e9800998ecf8427").is_err()); // 31 chars
        assert!(validate_hash("d41d8cd98f00b204e9800998ecf8427e1").is_err()); // 33 chars
        assert!(validate_hash("abc123").is_err()); // too short
    }

    #[test]
    fn test_validate_hash_invalid_characters() {
        assert!(validate_hash("d41d8cd98f00b204e9800998ecf8427g").is_err()); // invalid char 'g'
        assert!(validate_hash("d41d8cd98f00b204e9800998ecf8427z").is_err()); // invalid char 'z'
        assert!(validate_hash("d41d8cd98f00b204e9800998ecf8427!").is_err()); // invalid char '!'
        assert!(validate_hash("d41d8cd98f00b204e9800998ecf8427 ").is_err()); // space
    }

    #[test]
    fn test_validate_hash_mixed_case() {
        assert!(validate_hash("D41D8CD98F00B204E9800998ECF8427E").is_ok()); // uppercase
        assert!(validate_hash("d41d8cd98f00b204e9800998ecf8427e").is_ok()); // lowercase
        assert!(validate_hash("D41d8cD98F00b204E9800998ecF8427E").is_ok()); // mixed case
    }
}
