//
// Purpose:
//
// This Rust application implements an MCP (Model Context Protocol) server that acts as a
// bridge to a Cortex instance. It exposes various Cortex analyzer functionalities as
// tools that can be invoked by MCP clients (e.g., AI models, automation scripts).
//
// Structure:
// - `main()`: Entry point of the application. Initializes logging (tracing),
//   sets up the `CortexToolsServer`, and starts the MCP server using stdio transport.
//
// - `CortexToolsServer`: The core struct that implements the `rmcp::ServerHandler` trait
//   and the `#[tool(tool_box)]` attribute.
//   - It holds the configuration for connecting to the Cortex API.
//   - Its methods, decorated with `#[tool(...)]`, define the actual tools available
//     to MCP clients (e.g., `analyze_ip_with_abuseipdb`, `analyze_with_abusefinder`,
//     `scan_url_with_virustotal`).
//
// - Tool Parameter Structs (e.g., `AnalyzeIpParams`, `AnalyzeWithAbuseFinderParams`, `ScanUrlWithVirusTotalParams`):
//   - These structs define the expected input parameters for each tool.
//   - They use `serde::Deserialize` for parsing input and `schemars::JsonSchema`
//     for generating a schema that MCP clients can use to understand how to call the tools.
//
// - `common` module:
//   - `setup_cortex_configuration()`: Reads Cortex endpoint and API key from environment
//     variables and prepares the `cortex_client::apis::configuration::Configuration` object.
//   - `get_analyzer_id_by_name()`: Fetches all analyzer instances from Cortex and finds the
//     ID of a specific analyzer by its name. This is used to dynamically locate the
//     correct analyzer worker to run.
//   - `run_job_and_wait_for_report()`: A crucial helper function that encapsulates the
//     asynchronous workflow of:
//     1. Submitting a job to a specific Cortex analyzer.
//     2. Polling the job status until it completes (Success/Failure) or times out.
//     3. Fetching and returning the job report if successful.
//     It handles retries and error reporting for this multi-step process.
//
// Workflow:
// 1. Server starts and listens for MCP requests on stdio.
// 2. MCP client sends a `call_tool` request.
// 3. `CortexToolsServer` dispatches to the appropriate tool method based on the tool name.
// 4. The tool method parses parameters, interacts with the `common` module to:
//    a. Get the target Cortex analyzer's ID.
//    b. Create a job request with the provided data.
//    c. Submit the job and wait for the report.
// 5. The result (success with report or error) is packaged into a `CallToolResult`
//    and sent back to the MCP client.
//
// Configuration:
// The server requires `CORTEX_ENDPOINT` and `CORTEX_API_KEY` environment variables
// to connect to the Cortex instance. Logging is controlled by `RUST_LOG`.

use rmcp::{
    Error as McpError, ServerHandler, ServiceExt,
    model::{
        CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
    },
    schemars, tool,
    transport::stdio,
};
use serde_json::json;
use std::sync::Arc;

mod common {
    use cortex_client::apis::configuration::Configuration;
    use std::env;

    pub fn setup_cortex_configuration() -> Result<Configuration, String> {
        let base_path = env::var("CORTEX_ENDPOINT").map_err(|_| {
            "CORTEX_ENDPOINT environment variable not set. \
            Please set it to your Cortex API URL (e.g., http://localhost:9000/api)."
                .to_string()
        })?;

        let api_key = env::var("CORTEX_API_KEY").map_err(|_| {
            "CORTEX_API_KEY environment variable not set. \
            Please set your Cortex API key."
                .to_string()
        })?;

        let mut configuration = Configuration::new();
        configuration.base_path = base_path;
        configuration.bearer_access_token = Some(api_key);

        Ok(configuration)
    }

    pub async fn get_analyzer_id_by_name(
        config: &Configuration,
        analyzer_name_to_find: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        tracing::info!(
            "Fetching all analyzer instances to find ID for '{}'...",
            analyzer_name_to_find
        );

        let find_request = Some(cortex_client::models::AnalyzerFindRequest::default());

        match cortex_client::apis::analyzer_api::find_analyzers(config, find_request).await {
            Ok(analyzer_instances) => {
                for analyzer_instance in analyzer_instances {
                    if let Some(name) = &analyzer_instance.name {
                        if name == analyzer_name_to_find {
                            if let Some(id) = analyzer_instance._id {
                                tracing::info!(
                                    "Found analyzer ID '{}' for name '{}'",
                                    id,
                                    analyzer_name_to_find
                                );
                                return Ok(Some(id));
                            }
                        }
                    }
                }
                tracing::warn!("Analyzer with name '{}' not found.", analyzer_name_to_find);
                Ok(None)
            }
            Err(e) => {
                tracing::error!("Error fetching analyzer instances: {:?}", e);
                Err(Box::new(e))
            }
        }
    }

    pub async fn run_job_and_wait_for_report(
        config: &cortex_client::apis::configuration::Configuration,
        analyzer_worker_id: &str,
        job_request: cortex_client::models::JobCreateRequest,
        analyzer_name_for_log: &str,
        observable_for_log: &str,
    ) -> Result<cortex_client::models::JobReportResponse, Box<dyn std::error::Error>> {
        use cortex_client::apis::job_api;
        use std::time::Duration;

        tracing::info!(
            analyzer_name = %analyzer_name_for_log,
            analyzer_id = %analyzer_worker_id,
            observable = %observable_for_log,
            "Submitting job to analyzer"
        );

        match job_api::create_analyzer_job(config, analyzer_worker_id, job_request).await {
            Ok(job_response) => {
                let unknown_job_id = "unknown".to_string();
                let job_id_str = job_response._id.as_ref().unwrap_or(&unknown_job_id);
                tracing::info!(
                    job_id = %job_id_str,
                    status = ?job_response.status,
                    "Successfully created job"
                );

                if let Some(job_id) = job_response._id {
                    tracing::info!(
                        job_id = %job_id,
                        "Attempting to fetch report with retries"
                    );

                    let max_retries = 5;
                    let retry_delay = Duration::from_secs(5);

                    for attempt in 1..=max_retries {
                        tracing::info!(
                            job_id = %job_id,
                            attempt = %attempt,
                            max_retries = %max_retries,
                            "Attempting to check job status"
                        );
                        match job_api::get_job_by_id(config, &job_id).await {
                            Ok(job_details) => {
                                tracing::debug!(job_id = %job_id, attempt = %attempt, status = ?job_details.status, "Current job status");
                                match job_details.status {
                                    Some(cortex_client::models::job::Status::Success) => {
                                        tracing::info!(job_id = %job_id, attempt = %attempt, "Job status is Success. Attempting to fetch report");
                                        match job_api::get_job_report(config, &job_id).await {
                                            Ok(report_response) => {
                                                tracing::info!(job_id = %job_id, attempt = %attempt, "Successfully fetched job report");
                                                return Ok(report_response);
                                            }
                                            Err(e) => {
                                                let err_msg = format!(
                                                    "Error fetching job report for job_id '{}' (attempt {}) even though status was Success: {:?}",
                                                    job_id, attempt, e
                                                );
                                                tracing::error!("{}", err_msg);
                                                return Err(err_msg.into());
                                            }
                                        }
                                    }
                                    Some(cortex_client::models::job::Status::Failure) => {
                                        let err_msg = format!(
                                            "Job failed for job_id '{}' (attempt {}). Error message: {:?}",
                                            job_id,
                                            attempt,
                                            job_details.error_message.unwrap_or_else(|| Some(
                                                "No error message provided.".to_string()
                                            ))
                                        );
                                        tracing::error!("{}", err_msg);
                                        return Err(err_msg.into());
                                    }
                                    Some(cortex_client::models::job::Status::InProgress)
                                    | Some(cortex_client::models::job::Status::Waiting) => {
                                        if attempt < max_retries {
                                            tracing::info!(
                                                job_id = %job_id,
                                                attempt = %attempt,
                                                status = ?job_details.status.unwrap(),
                                                retry_delay_secs = %retry_delay.as_secs(),
                                                "Job is still in progress. Waiting before next attempt"
                                            );
                                            tokio::time::sleep(retry_delay).await;
                                        } else {
                                            let info_msg = format!(
                                                "Job (ID: '{}') did not complete (still {:?}) after {} attempts.",
                                                job_id,
                                                job_details.status.unwrap(),
                                                max_retries
                                            );
                                            tracing::warn!("{}", info_msg);
                                            return Err(info_msg.into());
                                        }
                                    }
                                    Some(cortex_client::models::job::Status::Deleted) => {
                                        let err_msg = format!(
                                            "Job (ID: '{}', attempt {}) has been deleted. Cannot fetch report.",
                                            job_id, attempt
                                        );
                                        tracing::error!("{}", err_msg);
                                        return Err(err_msg.into());
                                    }
                                    None => {
                                        let warn_msg = format!(
                                            "Job status is unknown for job_id '{}' (attempt {}). Cannot determine if report is ready.",
                                            job_id, attempt
                                        );
                                        tracing::warn!("{}", warn_msg);
                                        if attempt < max_retries {
                                            tokio::time::sleep(retry_delay).await;
                                        } else {
                                            let info_msg = format!(
                                                "Job status for job_id '{}' remained unknown after {} attempts.",
                                                job_id, max_retries
                                            );
                                            tracing::warn!("{}", info_msg);
                                            return Err(info_msg.into());
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                    job_id = %job_id,
                                    attempt = %attempt,
                                    error = ?e,
                                    "Error fetching job details"
                                );
                                if attempt == max_retries {
                                    let err_msg = format!(
                                        "Could not fetch job details after {} attempts for job ID: {}. Last error: {:?}",
                                        max_retries, job_id, e
                                    );
                                    tracing::error!("{}", err_msg);
                                    return Err(err_msg.into());
                                } else {
                                    tokio::time::sleep(retry_delay).await;
                                }
                            }
                        }
                    }
                    let final_err_msg = format!(
                        "Could not retrieve job report for job ID '{}' after {} attempts.",
                        job_id, max_retries
                    );
                    tracing::error!("{}", final_err_msg);
                    Err(final_err_msg.into())
                } else {
                    let err_msg = "Job created, but no job ID was returned in the response. Cannot fetch report.".to_string();
                    tracing::error!("{}", err_msg);
                    Err(err_msg.into())
                }
            }
            Err(e) => {
                let err_msg = format!(
                    "Error creating analyzer job for '{}' on '{}': {:?}",
                    analyzer_name_for_log, observable_for_log, e
                );
                tracing::error!("{}", err_msg);
                Err(err_msg.into())
            }
        }
    }
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct AnalyzeIpParams {
    #[schemars(description = "The IP address to analyze.")]
    ip: String,
    #[schemars(
        description = "Optional: The name of the AbuseIPDB analyzer instance in Cortex. Defaults to 'AbuseIPDB_1_0'."
    )]
    analyzer_name: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct AnalyzeWithAbuseFinderParams {
    #[schemars(
        description = "The data to analyze (e.g., an IP, domain, FQDN, URL, or email address)."
    )]
    data: String,
    #[schemars(
        description = "The type of the data. Must be one of: 'ip', 'domain', 'fqdn', 'url', 'mail'."
    )]
    data_type: String,
    #[schemars(
        description = "Optional: The name of the AbuseFinder analyzer instance in Cortex. Defaults to 'AbuseFinder_3_0'."
    )]
    analyzer_name: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ScanUrlWithVirusTotalParams {
    #[schemars(description = "The URL to scan.")]
    url: String,
    #[schemars(
        description = "Optional: The name of the VirusTotal_Scan analyzer instance in Cortex. Defaults to 'VirusTotal_Scan_3_1'."
    )]
    analyzer_name: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct AnalyzeUrlWithUrlscanIoParams {
    #[schemars(description = "The URL to scan.")]
    url: String,
    #[schemars(
        description = "Optional: The name of the Urlscan_io_Scan analyzer instance in Cortex. Defaults to 'Urlscan_io_Scan_0_1_0'."
    )]
    analyzer_name: Option<String>,
}

#[derive(Clone)]
struct CortexToolsServer {
    cortex_config: Arc<cortex_client::apis::configuration::Configuration>,
}

#[tool(tool_box)]
impl CortexToolsServer {
    fn new() -> Result<Self, anyhow::Error> {
        let cortex_config = common::setup_cortex_configuration()
            .map_err(|e| anyhow::anyhow!("Cortex configuration error: {}", e))?;
        Ok(Self {
            cortex_config: Arc::new(cortex_config),
        })
    }

    #[tool(
        name = "analyze_ip_with_abuseipdb",
        description = "Analyzes an IP address using AbuseIPDB via Cortex. Returns the job details or report if successful."
    )]
    async fn analyze_ip_with_abuseipdb(
        &self,
        #[tool(aggr)] params: AnalyzeIpParams,
    ) -> Result<CallToolResult, McpError> {
        let ip_to_analyze = params.ip;
        let analyzer_name_to_run = params
            .analyzer_name
            .unwrap_or_else(|| "AbuseIPDB_1_0".to_string());
        let data_type = "ip";

        tracing::info!(ip = %ip_to_analyze, analyzer = %analyzer_name_to_run, "Attempting IP analysis");

        let analyzer_worker_id = match common::get_analyzer_id_by_name(
            &self.cortex_config,
            &analyzer_name_to_run,
        )
        .await
        {
            Ok(Some(id)) => id,
            Ok(None) => {
                let err_msg = format!(
                    "Could not find an analyzer instance named '{}'. Ensure it's enabled in Cortex.",
                    analyzer_name_to_run
                );
                tracing::error!("{}", err_msg);
                return Ok(CallToolResult::error(vec![Content::text(err_msg)]));
            }
            Err(e) => {
                let err_msg = format!(
                    "Error getting analyzer ID for '{}': {}",
                    analyzer_name_to_run, e
                );
                tracing::error!("{}", err_msg);
                return Ok(CallToolResult::error(vec![Content::text(err_msg)]));
            }
        };

        tracing::info!(
            "Attempting to run analyzer '{}' (ID: '{}') on IP: {}",
            analyzer_name_to_run,
            analyzer_worker_id,
            ip_to_analyze
        );

        let job_create_request = cortex_client::models::JobCreateRequest {
            data: Some(ip_to_analyze.to_string()),
            data_type: Some(data_type.to_string()),
            tlp: Some(2), // AMBER
            pap: Some(2), // AMBER
            message: Some(Some(format!(
                "MCP Cortex Server: Analyzing IP {} with {}",
                ip_to_analyze, analyzer_name_to_run
            ))),
            parameters: None,
            label: Some(Some(format!("mcp_ip_analysis_{}", ip_to_analyze))),
            force: Some(false),
            attributes: None,
        };

        match common::run_job_and_wait_for_report(
            &self.cortex_config,
            &analyzer_worker_id,
            job_create_request,
            &analyzer_name_to_run,
            &ip_to_analyze,
        )
        .await
        {
            Ok(report_response) => {
                tracing::info!(
                    "Successfully obtained report for IP {} using analyzer {}",
                    ip_to_analyze,
                    analyzer_name_to_run
                );
                let success_content = json!({
                    "status": "success",
                    "report": report_response
                });
                Ok(CallToolResult::success(vec![
                    Content::json(success_content)
                        .map_err(|e| McpError::internal_error(e.to_string(), None))?,
                ]))
            }
            Err(e) => {
                let err_msg = format!(
                    "Error running analyzer '{}' for IP '{}' and waiting for report: {:?}",
                    analyzer_name_to_run, ip_to_analyze, e
                );
                tracing::error!("{}", err_msg);
                Ok(CallToolResult::error(vec![Content::text(err_msg)]))
            }
        }
    }

    #[tool(
        name = "analyze_with_abusefinder",
        description = "Analyzes data (IP, domain, FQDN, URL, or mail) using AbuseFinder via Cortex. Returns the job report if successful."
    )]
    async fn analyze_with_abusefinder(
        &self,
        #[tool(aggr)] params: AnalyzeWithAbuseFinderParams,
    ) -> Result<CallToolResult, McpError> {
        let data_to_analyze = params.data;
        let data_type = params.data_type.to_lowercase(); // Normalize to lowercase
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

        tracing::info!(
            data = %data_to_analyze,
            data_type = %data_type,
            analyzer = %analyzer_name_to_run,
            "Attempting analysis with AbuseFinder"
        );

        let analyzer_worker_id = match common::get_analyzer_id_by_name(
            &self.cortex_config,
            &analyzer_name_to_run,
        )
        .await
        {
            Ok(Some(id)) => id,
            Ok(None) => {
                let err_msg = format!(
                    "Could not find an analyzer instance named '{}'. Ensure it's enabled in Cortex.",
                    analyzer_name_to_run
                );
                tracing::error!("{}", err_msg);
                return Ok(CallToolResult::error(vec![Content::text(err_msg)]));
            }
            Err(e) => {
                let err_msg = format!(
                    "Error getting analyzer ID for '{}': {}",
                    analyzer_name_to_run, e
                );
                tracing::error!("{}", err_msg);
                return Ok(CallToolResult::error(vec![Content::text(err_msg)]));
            }
        };

        tracing::info!(
            "Attempting to run analyzer '{}' (ID: '{}') on data: {}, type: {}",
            analyzer_name_to_run,
            analyzer_worker_id,
            data_to_analyze,
            data_type
        );

        let job_create_request = cortex_client::models::JobCreateRequest {
            data: Some(data_to_analyze.clone()),
            data_type: Some(data_type.clone()),
            tlp: Some(2), // AMBER
            pap: Some(2), // AMBER
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

        match common::run_job_and_wait_for_report(
            &self.cortex_config,
            &analyzer_worker_id,
            job_create_request,
            &analyzer_name_to_run,
            &format!("{} ({})", data_to_analyze, data_type),
        )
        .await
        {
            Ok(report_response) => {
                tracing::info!(
                    "Successfully obtained report for data '{}' ({}) using analyzer {}",
                    data_to_analyze,
                    data_type,
                    analyzer_name_to_run
                );
                let success_content = json!({
                    "status": "success",
                    "report": report_response
                });
                Ok(CallToolResult::success(vec![
                    Content::json(success_content)
                        .map_err(|e| McpError::internal_error(e.to_string(), None))?,
                ]))
            }
            Err(e) => {
                let err_msg = format!(
                    "Error running analyzer '{}' for data '{}' ({}) and waiting for report: {:?}",
                    analyzer_name_to_run, data_to_analyze, data_type, e
                );
                tracing::error!("{}", err_msg);
                Ok(CallToolResult::error(vec![Content::text(err_msg)]))
            }
        }
    }

    #[tool(
        name = "scan_url_with_virustotal",
        description = "Scans a URL using VirusTotal_Scan_3_1 via Cortex. Returns the job report if successful."
    )]
    async fn scan_url_with_virustotal(
        &self,
        #[tool(aggr)] params: ScanUrlWithVirusTotalParams,
    ) -> Result<CallToolResult, McpError> {
        let url_to_scan = params.url;
        let analyzer_name_to_run = params
            .analyzer_name
            .unwrap_or_else(|| "VirusTotal_Scan_3_1".to_string());
        let data_type = "url"; // VirusTotal_Scan_3_1 operates on URLs

        tracing::info!(
            url = %url_to_scan,
            analyzer = %analyzer_name_to_run,
            "Attempting URL scan with VirusTotal"
        );

        let analyzer_worker_id = match common::get_analyzer_id_by_name(
            &self.cortex_config,
            &analyzer_name_to_run,
        )
        .await
        {
            Ok(Some(id)) => id,
            Ok(None) => {
                let err_msg = format!(
                    "Could not find an analyzer instance named '{}'. Ensure it's enabled in Cortex.",
                    analyzer_name_to_run
                );
                tracing::error!("{}", err_msg);
                return Ok(CallToolResult::error(vec![Content::text(err_msg)]));
            }
            Err(e) => {
                let err_msg = format!(
                    "Error getting analyzer ID for '{}': {}",
                    analyzer_name_to_run, e
                );
                tracing::error!("{}", err_msg);
                return Ok(CallToolResult::error(vec![Content::text(err_msg)]));
            }
        };

        tracing::info!(
            "Attempting to run analyzer '{}' (ID: '{}') on URL: {}",
            analyzer_name_to_run,
            analyzer_worker_id,
            url_to_scan
        );

        let job_create_request = cortex_client::models::JobCreateRequest {
            data: Some(url_to_scan.clone()),
            data_type: Some(data_type.to_string()),
            tlp: Some(2), // AMBER
            pap: Some(2), // AMBER
            message: Some(Some(format!(
                "MCP Cortex Server: Scanning URL {} with {}",
                url_to_scan, analyzer_name_to_run
            ))),
            parameters: None, // Add specific parameters if VirusTotal_Scan_3_1 requires them
            label: Some(Some(format!("mcp_url_scan_{}", url_to_scan))),
            force: Some(false),
            attributes: None,
        };

        match common::run_job_and_wait_for_report(
            &self.cortex_config,
            &analyzer_worker_id,
            job_create_request,
            &analyzer_name_to_run,
            &url_to_scan,
        )
        .await
        {
            Ok(report_response) => {
                tracing::info!(
                    "Successfully obtained report for URL '{}' using analyzer {}",
                    url_to_scan,
                    analyzer_name_to_run
                );
                let success_content = json!({
                    "status": "success",
                    "report": report_response
                });
                Ok(CallToolResult::success(vec![
                    Content::json(success_content)
                        .map_err(|e| McpError::internal_error(e.to_string(), None))?,
                ]))
            }
            Err(e) => {
                let err_msg = format!(
                    "Error running analyzer '{}' for URL '{}' and waiting for report: {:?}",
                    analyzer_name_to_run, url_to_scan, e
                );
                tracing::error!("{}", err_msg);
                Ok(CallToolResult::error(vec![Content::text(err_msg)]))
            }
        }
    }

    #[tool(
        name = "analyze_url_with_urlscan_io",
        description = "Analyzes a URL using the Urlscan.io analyzer via Cortex. Returns the job report if successful."
    )]
    async fn analyze_url_with_urlscan_io(
        &self,
        #[tool(aggr)] params: AnalyzeUrlWithUrlscanIoParams,
    ) -> Result<CallToolResult, McpError> {
        let url_to_analyze = params.url;
        let analyzer_name_to_run = params
            .analyzer_name
            .unwrap_or_else(|| "Urlscan_io_Scan_0_1_0".to_string());
        let data_type = "url";

        tracing::info!(
            url = %url_to_analyze,
            analyzer = %analyzer_name_to_run,
            "Attempting URL analysis with urlscan.io"
        );

        let analyzer_worker_id = match common::get_analyzer_id_by_name(
            &self.cortex_config,
            &analyzer_name_to_run,
        )
        .await
        {
            Ok(Some(id)) => id,
            Ok(None) => {
                let err_msg = format!(
                    "Could not find an analyzer instance named '{}'. Ensure it's enabled in Cortex.",
                    analyzer_name_to_run
                );
                tracing::error!("{}", err_msg);
                return Ok(CallToolResult::error(vec![Content::text(err_msg)]));
            }
            Err(e) => {
                let err_msg = format!(
                    "Error getting analyzer ID for '{}': {}",
                    analyzer_name_to_run, e
                );
                tracing::error!("{}", err_msg);
                return Ok(CallToolResult::error(vec![Content::text(err_msg)]));
            }
        };

        tracing::info!(
            "Attempting to run analyzer '{}' (ID: '{}') on URL: {}",
            analyzer_name_to_run,
            analyzer_worker_id,
            url_to_analyze
        );

        let job_create_request = cortex_client::models::JobCreateRequest {
            data: Some(url_to_analyze.clone()),
            data_type: Some(data_type.to_string()),
            tlp: Some(2), // AMBER
            pap: Some(2), // AMBER
            message: Some(Some(format!(
                "MCP Cortex Server: Analyzing URL {} with {}",
                url_to_analyze, analyzer_name_to_run
            ))),
            parameters: None,
            label: Some(Some(format!("mcp_urlscanio_analysis_{}", url_to_analyze))),
            force: Some(false),
            attributes: None,
        };

        match common::run_job_and_wait_for_report(
            &self.cortex_config,
            &analyzer_worker_id,
            job_create_request,
            &analyzer_name_to_run,
            &url_to_analyze,
        )
        .await
        {
            Ok(report_response) => {
                tracing::info!(
                    "Successfully obtained report for URL {} using analyzer {}",
                    url_to_analyze,
                    analyzer_name_to_run
                );
                let success_content = json!({
                    "status": "success",
                    "report": report_response
                });
                Ok(CallToolResult::success(vec![
                    Content::json(success_content)
                        .map_err(|e| McpError::internal_error(e.to_string(), None))?,
                ]))
            }
            Err(e) => {
                let err_msg = format!(
                    "Error running analyzer '{}' for URL '{}' and waiting for report: {:?}",
                    analyzer_name_to_run, url_to_analyze, e
                );
                tracing::error!("{}", err_msg);
                Ok(CallToolResult::error(vec![Content::text(err_msg)]))
            }
        }
    }
}

#[tool(tool_box)]
impl ServerHandler for CortexToolsServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_prompts()
                .enable_resources()
                .enable_tools()
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "This server provides tools to interact with a Cortex instance for threat intelligence analysis.\n\
                Available tools:\n\
                - 'analyze_ip_with_abuseipdb': Analyzes an IP address using the AbuseIPDB analyzer. \
                Requires 'ip' and optionally 'analyzer_name' (defaults to 'AbuseIPDB_1_0').\n\
                - 'analyze_with_abusefinder': Analyzes data (IP, domain, FQDN, URL, or mail) using the AbuseFinder analyzer. \
                Requires 'data', 'data_type' (one of 'ip', 'domain', 'fqdn', 'url', 'mail'), and optionally 'analyzer_name' (defaults to 'AbuseFinder_3_0').\n\
                - 'scan_url_with_virustotal': Scans a URL using the VirusTotal analyzer. Requires 'url' and optionally 'analyzer_name' (defaults to 'VirusTotal_Scan_3_1').\n\
                - 'analyze_url_with_urlscan_io': Analyzes a URL using the Urlscan.io analyzer. Requires 'url' and optionally 'analyzer_name' (defaults to 'Urlscan_io_Scan_0_1_0')."
                    .to_string(),
            ),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::DEBUG.into()),
        )
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("Starting MCP Cortex Server...");

    // Create an instance of our counter router
    let service = CortexToolsServer::new()
        .expect("Error initializing")
        .serve(stdio())
        .await
        .inspect_err(|e| {
            tracing::error!("serving error: {:?}", e);
        })?;

    service.waiting().await?;
    Ok(())
}
