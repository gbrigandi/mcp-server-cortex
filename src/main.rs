//
// Purpose:
//
// This Rust application implements an MCP (Model Context Protocol) server that acts as a
// bridge to a Cortex instance. It exposes various Cortex analyzer functionalities as
// tools that can be invoked by MCP clients (e.g., AI models, automation scripts).
//
// The exposed tools are:
// - `analyze_ip_with_abuseipdb`: Analyzes an IP address using the AbuseIPDB analyzer.
// - `analyze_with_abusefinder`: Analyzes data (IP, domain, FQDN, URL, or mail) using the AbuseFinder analyzer.
// - `scan_url_with_virustotal`: Scans a URL using the VirusTotal_Scan_3_1 analyzer.
// - `analyze_url_with_urlscan_io`: Analyzes a URL using the Urlscan.io analyzer.
// - `scan_hash_with_virustotal`: Scans a hash using the VirusTotal_GetReport_3_1 analyzer.
//
// Structure:
// - `main()`: Entry point of the application. Initializes logging (tracing),
//   sets up the `CortexToolsServer`, and starts the MCP server using stdio transport.
//
// - `CortexToolsServer`: The core struct that implements the `rmcp::ServerHandler` trait.
//   - It holds the configuration for connecting to the Cortex API.
//   - Its methods, decorated with `#[tool(...)]` and routed via `#[tool_router]`, define
//     the actual tools available to MCP clients (e.g., `analyze_ip_with_abuseipdb`,
//     `analyze_with_abusefinder`, `scan_url_with_virustotal`).
//
// - Tool Parameter Structs (e.g., `AnalyzeIpParams`, `AnalyzeWithAbuseFinderParams`):
//   - These structs define the expected input parameters for each tool.
//   - They use `serde::Deserialize` for parsing input and `schemars::JsonSchema`
//     for generating a schema that MCP clients can use to understand how to call the tools.
//
// - Helper Functions:
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
// 4. The tool method parses parameters and uses the helper functions to:
//    a. Get the target Cortex analyzer's ID.
//    b. Create a job request with the provided data.
//    c. Submit the job and wait for the report.
// 5. The result (success with report or error) is packaged into a `CallToolResult`
//    and sent back to the MCP client.
//
// Configuration:
// The server requires `CORTEX_ENDPOINT` and `CORTEX_API_KEY` environment variables
// to connect to the Cortex instance. Logging is controlled by `RUST_LOG`.
//
use anyhow::Result;
use cortex_client::apis::configuration::Configuration;
use rmcp::{
    handler::server::{
        tool::{Parameters, ToolRouter},
        ServerHandler,
    },
    model::*,
    service::ServiceExt,
    tool, tool_handler, tool_router, schemars, ErrorData,
};
use serde_json::json;
use std::{env, sync::Arc, future::Future};
use tokio;

// --- Structs for Tool Parameters ---

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


// --- Main Server Struct and Implementations ---

#[derive(Clone)]
struct CortexToolsServer {
    cortex_config: Arc<cortex_client::apis::configuration::Configuration>,
    tool_router: ToolRouter<CortexToolsServer>,
}

impl CortexToolsServer {
    fn new() -> Result<Self> {
        let cortex_config = setup_cortex_configuration()
            .map_err(|e| anyhow::anyhow!("Cortex configuration error: {}", e))?;
        Ok(Self {
            cortex_config: Arc::new(cortex_config),
            tool_router: CortexToolsServer::tool_router(),
        })
    }
}

#[tool_handler]
impl ServerHandler for CortexToolsServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "This server provides tools to interact with a Cortex instance for threat intelligence analysis.".to_string()
            ),
        }
    }
}

#[tool_router]
impl CortexToolsServer {
    #[tool(description = "Analyzes an IP address using AbuseIPDB via Cortex.")]
    async fn analyze_ip_with_abuseipdb(
        &self,
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

        run_analyzer_and_get_report(
            &self.cortex_config,
            &analyzer_name_to_run,
            job_create_request,
            &ip_to_analyze,
            params.max_retries.unwrap_or(5),
        )
        .await
    }

    #[tool(description = "Analyzes data (IP, domain, FQDN, URL, or mail) using AbuseFinder via Cortex.")]
    async fn analyze_with_abusefinder(
        &self,
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

        run_analyzer_and_get_report(
            &self.cortex_config,
            &analyzer_name_to_run,
            job_create_request,
            &format!("{} ({})", data_to_analyze, data_type),
            params.max_retries.unwrap_or(5),
        )
        .await
    }

    #[tool(description = "Scans a URL using VirusTotal_Scan_3_1 via Cortex.")]
    async fn scan_url_with_virustotal(
        &self,
        Parameters(params): Parameters<ScanUrlWithVirusTotalParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let url_to_scan = params.url;
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

        run_analyzer_and_get_report(
            &self.cortex_config,
            &analyzer_name_to_run,
            job_create_request,
            &url_to_scan,
            params.max_retries.unwrap_or(5),
        )
        .await
    }

    #[tool(description = "Analyzes a URL using the Urlscan.io analyzer via Cortex.")]
    async fn analyze_url_with_urlscan_io(
        &self,
        Parameters(params): Parameters<AnalyzeUrlWithUrlscanIoParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let url_to_analyze = params.url;
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

        run_analyzer_and_get_report(
            &self.cortex_config,
            &analyzer_name_to_run,
            job_create_request,
            &url_to_analyze,
            params.max_retries.unwrap_or(5),
        )
        .await
    }

    #[tool(description = "Scans a hash using VirusTotal_GetReport_3_1 via Cortex.")]
    async fn scan_hash_with_virustotal(
        &self,
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

        run_analyzer_and_get_report(
            &self.cortex_config,
            &analyzer_name_to_run,
            job_create_request,
            &hash_to_scan,
            params.max_retries.unwrap_or(5),
        )
        .await
    }
}

// --- Helper Functions ---

fn setup_cortex_configuration() -> Result<Configuration, String> {
    let base_path = env::var("CORTEX_ENDPOINT").map_err(|_| {
        "CORTEX_ENDPOINT environment variable not set. Please set it to your Cortex API URL (e.g., http://localhost:9000/api).".to_string()
    })?;

    let api_key = env::var("CORTEX_API_KEY").map_err(|_| {
        "CORTEX_API_KEY environment variable not set. Please set your Cortex API key.".to_string()
    })?;

    let mut configuration = Configuration::new();
    configuration.base_path = base_path;
    configuration.bearer_access_token = Some(api_key);

    Ok(configuration)
}

async fn run_analyzer_and_get_report(
    config: &Configuration,
    analyzer_name: &str,
    job_request: cortex_client::models::JobCreateRequest,
    observable_for_log: &str,
    max_retries: usize,
) -> Result<CallToolResult, ErrorData> {
    tracing::info!(
        analyzer = %analyzer_name,
        observable = %observable_for_log,
        "Attempting to run analyzer"
    );

    let analyzer_worker_id = match get_analyzer_id_by_name(config, analyzer_name).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            let err_msg = format!(
                "Could not find an analyzer instance named '{}'. Ensure it's enabled in Cortex.",
                analyzer_name
            );
            tracing::error!("{}", err_msg);
            return Ok(CallToolResult::error(vec![Content::text(err_msg)]));
        }
        Err(e) => {
            let err_msg = format!("Error getting analyzer ID for '{}': {}", analyzer_name, e);
            tracing::error!("{}", err_msg);
            return Ok(CallToolResult::error(vec![Content::text(err_msg)]));
        }
    };

    match run_job_and_wait_for_report(
        config,
        &analyzer_worker_id,
        job_request,
        analyzer_name,
        observable_for_log,
        max_retries,
    )
    .await
    {
        Ok(report_response) => {
            tracing::info!(
                "Successfully obtained report for observable {} using analyzer {}",
                observable_for_log,
                analyzer_name
            );
            let success_content = json!({
                "status": "success",
                "report": report_response
            });
            Ok(CallToolResult::success(vec![Content::json(
                success_content,
            )
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?]))
        }
        Err(e) => {
            let err_msg = format!(
                "Error running analyzer '{}' for observable '{}' and waiting for report: {:?}",
                analyzer_name, observable_for_log, e
            );
            tracing::error!("{}", err_msg);
            Ok(CallToolResult::error(vec![Content::text(err_msg)]))
        }
    }
}

async fn get_analyzer_id_by_name(
    config: &Configuration,
    analyzer_name_to_find: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let find_request = Some(cortex_client::models::AnalyzerFindRequest::default());
    let analyzer_instances = cortex_client::apis::analyzer_api::find_analyzers(config, find_request).await?;
    
    for analyzer_instance in analyzer_instances {
        if let Some(name) = &analyzer_instance.name {
            if name == analyzer_name_to_find {
                if let Some(id) = analyzer_instance._id {
                    return Ok(Some(id));
                }
            }
        }
    }
    Ok(None)
}

async fn run_job_and_wait_for_report(
    config: &Configuration,
    analyzer_worker_id: &str,
    job_request: cortex_client::models::JobCreateRequest,
    _analyzer_name_for_log: &str,
    _observable_for_log: &str,
    max_retries: usize,
) -> Result<cortex_client::models::JobReportResponse, Box<dyn std::error::Error>> {
    use cortex_client::apis::job_api;
    use std::time::Duration;

    let job_response = job_api::create_analyzer_job(config, analyzer_worker_id, job_request).await?;
    let job_id = job_response._id.ok_or("No job ID returned")?;

    for attempt in 1..=max_retries {
        let job_details = job_api::get_job_by_id(config, &job_id).await?;
        match job_details.status {
            Some(cortex_client::models::job::Status::Success) => {
                return Ok(job_api::get_job_report(config, &job_id).await?);
            }
            Some(cortex_client::models::job::Status::Failure) => {
                let err_msg = format!("Job failed: {:?}", job_details.error_message);
                return Err(err_msg.into());
            }
            _ => {
                if attempt < max_retries {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    Err("Job did not complete in time.".into())
}


// --- Main Function ---

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::DEBUG.into()),
        )
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("Starting MCP Cortex Server...");

    let service = CortexToolsServer::new()?;
    let transport = rmcp::transport::stdio();
    let server = service.serve(transport).await?;
    
    server.waiting().await?;

    Ok(())
}
