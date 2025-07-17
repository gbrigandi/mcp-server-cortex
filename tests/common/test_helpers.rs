//! Test helper functions and utilities

use mcp_server_cortex::CortexToolsServer;
use rmcp::{
    model::*,
    service::ServiceExt,
};
use serde_json::Value;
use std::env;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

use super::MockCortexServer;

/// Test wrapper around CortexToolsServer for integration testing
pub struct TestCortexServer {
    server: CortexToolsServer,
    _mock_cortex: MockCortexServer,
}

impl TestCortexServer {
    pub async fn new_with_mock(mock_cortex: &MockCortexServer) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Set environment variables to point to mock server
        unsafe {
            env::set_var("CORTEX_ENDPOINT", format!("{}/api", mock_cortex.base_url));
            env::set_var("CORTEX_API_KEY", "test-api-key");
        }
        
        let server = CortexToolsServer::new()?;
        
        Ok(TestCortexServer {
            server,
            _mock_cortex: mock_cortex.clone(),
        })
    }
    
    pub async fn serve<T>(&self, transport: T) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let server = self.server.clone().serve(transport).await?;
        server.waiting().await?;
        Ok(())
    }
}

/// Simple MCP client for testing tool invocations
pub struct TestMcpClient {
    writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    reader: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    next_id: u64,
    cancellation_token: CancellationToken,
}

impl TestMcpClient {
    pub fn new(stream: tokio::io::DuplexStream) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            writer,
            reader,
            next_id: 1,
            cancellation_token: CancellationToken::new(),
        }
    }
    
    pub async fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let init_request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        });
        
        self.send_request(init_request).await?;
        let _response = self.read_response().await?;
        
        // Send initialized notification
        let initialized_notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        
        self.send_request(initialized_notification).await?;
        
        Ok(())
    }
    
    pub async fn call_tool(&mut self, tool_name: &str, arguments: Value) -> Result<CallToolResult, Box<dyn std::error::Error + Send + Sync>> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        });
        
        self.send_request(request).await?;
        let response = self.read_response().await?;
        
        // Parse the response - return a simple result indicator
        if let Some(result) = response.get("result") {
            if let Some(content) = result.get("content") {
                return Ok(CallToolResult::success(
                    content.as_array()
                        .unwrap_or(&vec![])
                        .iter()
                        .map(|v| {
                            if let Some(text) = v.get("text") {
                                Content::text(text.as_str().unwrap_or(""))
                            } else {
                                Content::json(v.clone()).unwrap_or(Content::text(""))
                            }
                        })
                        .collect()
                ));
            }
        }
        
        if let Some(error) = response.get("error") {
            return Ok(CallToolResult::error(vec![
                Content::text(error.get("message").and_then(|m| m.as_str()).unwrap_or("Unknown error"))
            ]));
        }
        
        Ok(CallToolResult::error(vec![Content::text("Invalid response format")]))
    }
    
    async fn send_request(&mut self, request: Value) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use tokio::io::AsyncWriteExt;
        
        let request_str = serde_json::to_string(&request)?;
        self.writer.write_all(request_str.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await?;
        self.next_id += 1;
        
        Ok(())
    }
    
    async fn read_response(&mut self) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        use tokio::io::AsyncBufReadExt;
        
        let mut reader = tokio::io::BufReader::new(&mut self.reader);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        
        let response: Value = serde_json::from_str(&line)?;
        Ok(response)
    }
    
    pub fn cancel(&self) {
        self.cancellation_token.cancel();
    }
}

/// Test data generators
pub mod test_data {
    use serde_json::{json, Value};
    
    pub fn valid_ip_params() -> Value {
        json!({
            "ip": "8.8.8.8"
        })
    }
    
    pub fn private_ip_params() -> Value {
        json!({
            "ip": "192.168.1.1"
        })
    }
    
    pub fn invalid_ip_params() -> Value {
        json!({
            "ip": "256.256.256.256"
        })
    }
    
    pub fn valid_url_params() -> Value {
        json!({
            "url": "https://example.com"
        })
    }
    
    pub fn invalid_url_params() -> Value {
        json!({
            "url": "javascript:alert('xss')"
        })
    }
    
    pub fn valid_hash_params() -> Value {
        json!({
            "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        })
    }
    
    pub fn invalid_hash_params() -> Value {
        json!({
            "hash": "invalid-hash"
        })
    }
    
    pub fn valid_generic_params() -> Value {
        json!({
            "data": "example.com",
            "data_type": "domain"
        })
    }
}