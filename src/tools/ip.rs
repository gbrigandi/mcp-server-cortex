///
/// This module contains tools for analyzing IP addresses.
///
use crate::cortex;
use rmcp::{
    handler::server::tool::Parameters,
    model::*,
    schemars, ErrorData,
};

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
