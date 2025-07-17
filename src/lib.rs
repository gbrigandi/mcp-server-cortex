pub mod cortex;
pub mod tools;

use anyhow::Result;
use rmcp::{
    handler::server::{tool::{Parameters, ToolRouter}, ServerHandler},
    model::*,
    service::RequestContext,
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
            capabilities: ServerCapabilities::builder().enable_tools().enable_prompts().enable_prompts_list_changed().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "This server provides tools to interact with a Cortex instance for threat intelligence analysis.".to_string(),
            ),
        }
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParam>,
        _: RequestContext<rmcp::RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        Ok(ListPromptsResult {
            next_cursor: None,
            prompts: vec![Prompt::new(
                "soc_analyst",
                Some("You are an expert SOC analyst with 8+ years experience in cybersecurity incident response and threat intelligence analysis using Cortex. Use the available tools to analyze observables and provide comprehensive threat intelligence reports."),
                Some(vec![PromptArgument {
                    name: "incident_context".to_string(),
                    description: Some("Context about the security incident or observables to analyze (optional)".to_string()),
                    required: Some(false),
                }]),
            )],
        })
    }

    async fn get_prompt(
        &self,
        GetPromptRequestParam { name, arguments }: GetPromptRequestParam,
        _: RequestContext<rmcp::RoleServer>,
    ) -> Result<GetPromptResult, ErrorData> {
        match name.as_str() {
            "soc_analyst" => {
                let incident_context = arguments
                    .and_then(|json| json.get("incident_context")?.as_str().map(|s| s.to_string()))
                    .unwrap_or_else(|| "No specific incident context provided".to_string());

                let prompt = format!(
                    r#"You are an expert SOC analyst with 8+ years experience in cybersecurity incident response and threat intelligence analysis using Cortex.

Core Skills: Threat hunting, observable analysis, MITRE ATT&CK mapping, Cortex analyzer management, automated threat intel workflows, IOC validation.

Observable Expertise: IP reputation and geolocation, domain/URL malware detection, file hash analysis, email phishing detection, network behavioral analysis.

Approach: Consider full attack lifecycle, prioritize by threat severity, think in TTPs, reduce false positives, emphasize context over isolated indicators.

Analysis Framework: 
1) Assess severity and impact 
2) Identify observables for Cortex analysis 
3) Correlate threat intel and TTPs 
4) Recommend investigation steps 
5) Provide containment actions 
6) Suggest improvements

Available Cortex Tools:
- `analyze_ip_with_abuseipdb`: Analyzes IP addresses using AbuseIPDB reputation service
- `analyze_with_abusefinder`: Analyzes IPs, domains, FQDNs, URLs, or email addresses using AbuseFinder
- `scan_url_with_virustotal`: Scans URLs using VirusTotal URL scanner
- `scan_hash_with_virustotal`: Scans file hashes using VirusTotal hash lookup

Cortex Recommendations:
- IPs: Use analyze_ip_with_abuseipdb or analyze_with_abusefinder
- Domains/URLs: Use scan_url_with_virustotal or analyze_with_abusefinder
- File Hashes: Use scan_hash_with_virustotal
- Email addresses: Use analyze_with_abusefinder

Communication: Be clear and actionable, reference threat intel sources and MITRE techniques, stay concise but thorough. Always mask hostnames, IPs, domains and PII using formats like [MASKED-IP-XX.XX.XX.XX].

Focus on efficient threat intelligence analysis through intelligent automation and comprehensive observable investigation.

Incident Context: {}

Please analyze the provided observables and provide a comprehensive threat intelligence assessment using the available Cortex tools."#,
                    incident_context
                );

                Ok(GetPromptResult {
                    description: None,
                    messages: vec![PromptMessage {
                        role: PromptMessageRole::User,
                        content: PromptMessageContent::text(prompt),
                    }],
                })
            }
            _ => Err(ErrorData::invalid_params("prompt not found", None)),
        }
    }
}