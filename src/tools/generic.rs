///
/// This module contains generic tools that can be used to analyze various types of data.
///
use crate::cortex;
use rmcp::{
    handler::server::tool::Parameters,
    model::*,
    schemars, ErrorData,
};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AnalyzeWithAbuseFinderParams {
    #[schemars(
        description = "The data to analyze (e.g., an IP, domain, FQDN, URL, or email address)."
    )]
    pub data: String,
    #[schemars(
        description = "The type of the data. Must be one of: 'ip', 'domain', 'fqdn', 'url', 'mail'."
    )]
    pub data_type: String,
    #[schemars(
        description = "Optional: The name of the AbuseFinder analyzer instance in Cortex. Defaults to 'AbuseFinder_3_0'."
    )]
    pub analyzer_name: Option<String>,
    #[schemars(description = "Optional: Maximum number of retries to wait for the analyzer job to complete. Defaults to 5.")]
    pub max_retries: Option<usize>,
}

pub async fn analyze_with_abusefinder(
    server: &crate::CortexToolsServer,
    Parameters(params): Parameters<AnalyzeWithAbuseFinderParams>,
) -> Result<CallToolResult, ErrorData> {
    let data_to_analyze = params.data;
    let data_type = params.data_type.to_lowercase();
    let analyzer_name_to_run = params
        .analyzer_name
        .unwrap_or_else(|| "Abuse_Finder_3_0".to_string());

    let allowed_data_types = ["ip", "domain", "fqdn", "url", "mail"];
    if !allowed_data_types.contains(&data_type.as_str()) {
        let err_msg = format!(
            "Invalid data_type '{}'. Must be one of: {:?}",
            data_type, allowed_data_types
        );
        tracing::error!("{}", err_msg);
        return Ok(CallToolResult::error(vec![Content::text(err_msg)]));
    }

    let job_create_request = cortex_client::models::JobCreateRequest {
        data: Some(data_to_analyze.clone()),
        data_type: Some(data_type.clone()),
        tlp: Some(2),
        pap: Some(2),
        message: Some(Some(format!(
            "MCP Cortex Server: Analyzing {} ({}) with {}",
            data_to_analyze, data_type, analyzer_name_to_run
        ))),
        parameters: None,
        label: Some(Some(format!(
            "mcp_{}_analysis_{}",
            data_type, data_to_analyze
        ))),
        force: Some(false),
        attributes: None,
    };

    cortex::run_analyzer_and_get_report(
        &server.cortex_config,
        &analyzer_name_to_run,
        job_create_request,
        &format!("{} ({})", data_to_analyze, data_type),
        params.max_retries.unwrap_or(5),
    )
    .await
}
