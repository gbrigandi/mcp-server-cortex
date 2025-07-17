pub mod cortex;
pub mod tools;

use anyhow::Result;
use rmcp::{
    handler::server::{tool::{Parameters, ToolRouter}, ServerHandler},
    model::*,
    tool, tool_handler, tool_router,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct CortexToolsServer {
    pub cortex_config: Arc<cortex_client::apis::configuration::Configuration>,
    pub tool_router: ToolRouter<CortexToolsServer>,
}

#[tool_router]
impl CortexToolsServer {
    pub fn new() -> Result<Self> {
        let cortex_config = cortex::setup_cortex_configuration()
            .map_err(|e| anyhow::anyhow!("Cortex configuration error: {}", e))?;
        Ok(Self {
            cortex_config: Arc::new(cortex_config),
            tool_router: Self::tool_router(),
        })
    }

    #[tool(description = "Analyzes an IP address using AbuseIPDB via Cortex.")]
    async fn analyze_ip_with_abuseipdb(
        &self,
        Parameters(params): Parameters<tools::ip::AnalyzeIpParams>,
    ) -> Result<CallToolResult, ErrorData> {
        tools::ip::analyze_ip_with_abuseipdb(self, Parameters(params)).await
    }

    #[tool(description = "Analyzes data (IP, domain, FQDN, URL, or mail) using AbuseFinder via Cortex.")]
    async fn analyze_with_abusefinder(
        &self,
        Parameters(params): Parameters<tools::generic::AnalyzeWithAbuseFinderParams>,
    ) -> Result<CallToolResult, ErrorData> {
        tools::generic::analyze_with_abusefinder(self, Parameters(params)).await
    }

    #[tool(description = "Scans a URL using VirusTotal_Scan_3_1 via Cortex.")]
    async fn scan_url_with_virustotal(
        &self,
        Parameters(params): Parameters<tools::url::ScanUrlWithVirusTotalParams>,
    ) -> Result<CallToolResult, ErrorData> {
        tools::url::scan_url_with_virustotal(self, Parameters(params)).await
    }

    #[tool(description = "Analyzes a URL using the Urlscan.io analyzer via Cortex.")]
    async fn analyze_url_with_urlscan_io(
        &self,
        Parameters(params): Parameters<tools::url::AnalyzeUrlWithUrlscanIoParams>,
    ) -> Result<CallToolResult, ErrorData> {
        tools::url::analyze_url_with_urlscan_io(self, Parameters(params)).await
    }

    #[tool(description = "Scans a hash using VirusTotal_GetReport_3_1 via Cortex.")]
    async fn scan_hash_with_virustotal(
        &self,
        Parameters(params): Parameters<tools::hash::ScanHashWithVirusTotalParams>,
    ) -> Result<CallToolResult, ErrorData> {
        tools::hash::scan_hash_with_virustotal(self, Parameters(params)).await
    }
}

#[tool_handler]
impl ServerHandler for CortexToolsServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "This server provides tools to interact with a Cortex instance for threat intelligence analysis.".to_string(),
            ),
        }
    }
}