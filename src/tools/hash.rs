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
