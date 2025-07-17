/// # Purpose
///
/// This Rust application implements an MCP (Model Context Protocol) server that acts as a
/// bridge to a Cortex instance. It exposes various Cortex analyzer functionalities as
/// tools that can be invoked by MCP clients (e.g., AI models, automation scripts).
///
/// ## The exposed tools are:
/// - `analyze_ip_with_abuseipdb`: Analyzes an IP address using the AbuseIPDB analyzer via Cortex.
/// - `analyze_with_abusefinder`: Analyzes data (IP, domain, FQDN, URL, or mail) using the AbuseFinder analyzer via Cortex.
/// - `scan_url_with_virustotal`: Scans a URL using the VirusTotal_Scan_3_1 analyzer via Cortex.
/// - `analyze_url_with_urlscan_io`: Analyzes a URL using the Urlscan.io analyzer via Cortex.
/// - `scan_hash_with_virustotal`: Scans a hash using the VirusTotal_GetReport_3_1 analyzer via Cortex.
///
/// # Structure
/// - `main()`: Entry point of the application. Initializes logging (tracing),
///   sets up the `CortexToolsServer`, and starts the MCP server using stdio transport.
///
/// - `CortexToolsServer`: The core struct that implements the `rmcp::ServerHandler` trait.
///   - It holds the configuration for connecting to the Cortex API and a `ToolRouter` instance.
///   - Its methods, decorated with `#[tool(...)]` and routed via `#[tool_router]`, define
///     the actual tools available to MCP clients. Each tool method acts as a dispatcher
///     that delegates to the corresponding function in the `tools` module.
///
/// - Tool Parameter Structs (defined in `tools` module):
///   - Each tool module (ip, generic, url, hash) defines its own parameter structs.
///   - These structs use `serde::Deserialize` for parsing input and `schemars::JsonSchema`
///     for generating schemas that MCP clients can use to understand tool interfaces.
///
/// - `cortex` module:
///   - `setup_cortex_configuration()`: Reads Cortex endpoint and API key from environment
///     variables and prepares the `cortex_client::apis::configuration::Configuration` object.
///   - `run_analyzer_and_get_report()`: A crucial helper function that encapsulates the
///     asynchronous workflow of:
///     1. Submitting a job to a specific Cortex analyzer.
///     2. Polling the job status until it completes (Success/Failure) or times out.
///     3. Fetching and returning the job report if successful.
///        It handles retries and error reporting for this multi-step process.
///
/// # Workflow
/// 1. Server starts and listens for MCP requests on stdio.
/// 2. MCP client sends a `call_tool` request.
/// 3. `CortexToolsServer` dispatches to the appropriate tool method based on the tool name.
/// 4. The tool method delegates to the corresponding function in the `tools` module.
/// 5. The tool function parses parameters and uses the `cortex` module helper functions to:
///    a. Get the target Cortex analyzer's ID.
///    b. Create a job request with the provided data.
///    c. Submit the job and wait for the report.
/// 6. The result (success with report or error) is packaged into a `CallToolResult`
///    and sent back to the MCP client.
///
/// # Configuration
/// The server requires `CORTEX_ENDPOINT` and `CORTEX_API_KEY` environment variables
/// to connect to the Cortex instance. Logging is controlled by `RUST_LOG`.
///
use anyhow::Result;
use rmcp::service::ServiceExt;
use mcp_server_cortex::CortexToolsServer;

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
