//! Integration tests for the MCP Cortex Server
//!
//! These tests verify the full MCP server-client communication flow,
//! including tool invocations, validation, and error handling.

use std::env;
use mcp_server_cortex::CortexToolsServer;
use tokio::time::{timeout, Duration};

mod common;
use common::{MockCortexServer, TestCortexServer, TestMcpClient, test_data};

/// Test the basic MCP server initialization and tool listing
#[tokio::test]
async fn test_server_initialization() {
    let mock_cortex = MockCortexServer::start().await.unwrap();
    let test_server = TestCortexServer::new_with_mock(&mock_cortex).await.unwrap();
    
    let (server_transport, client_transport) = tokio::io::duplex(4096);
    
    // Spawn server
    let server_handle = tokio::spawn(async move {
        test_server.serve(server_transport).await
    });
    
    // Create client and initialize
    let mut client = TestMcpClient::new(client_transport);
    let init_result = timeout(Duration::from_secs(5), client.initialize()).await;
    
    assert!(init_result.is_ok(), "Server initialization should succeed");
    
    // Cleanup
    client.cancel();
    server_handle.abort();
}

/// Test IP analysis with AbuseIPDB - successful case
#[tokio::test]
async fn test_ip_analysis_success() {
    let mock_cortex = MockCortexServer::start().await.unwrap();
    let test_server = TestCortexServer::new_with_mock(&mock_cortex).await.unwrap();
    
    let (server_transport, client_transport) = tokio::io::duplex(4096);
    
    // Spawn server
    let server_handle = tokio::spawn(async move {
        test_server.serve(server_transport).await
    });
    
    // Create client and test tool
    let mut client = TestMcpClient::new(client_transport);
    client.initialize().await.unwrap();
    
    let result = timeout(
        Duration::from_secs(5),
        client.call_tool("analyze_ip_with_abuseipdb", test_data::valid_ip_params())
    ).await;
    
    assert!(result.is_ok(), "Tool call should complete");
    let tool_result = result.unwrap().unwrap();
    
    let content_str = format!("{:?}", tool_result);
    if content_str.contains("Invalid IP") || content_str.contains("Invalid URL") || content_str.contains("Invalid hash") {
        panic!("Expected success but got validation error: {:?}", tool_result);
    }
    
    // For success case, just verify we got some content
    assert!(content_str.contains("8.8.8.8") || content_str.contains("abuseConfidencePercentage") || content_str.contains("Success"));
    
    // Cleanup
    client.cancel();
    server_handle.abort();
}

/// Test URL scanning with VirusTotal - successful case
#[tokio::test]
async fn test_url_scan_success() {
    let mock_cortex = MockCortexServer::start().await.unwrap();
    let test_server = TestCortexServer::new_with_mock(&mock_cortex).await.unwrap();
    
    let (server_transport, client_transport) = tokio::io::duplex(4096);
    
    // Spawn server
    let server_handle = tokio::spawn(async move {
        test_server.serve(server_transport).await
    });
    
    // Create client and test tool
    let mut client = TestMcpClient::new(client_transport);
    client.initialize().await.unwrap();
    
    let result = timeout(
        Duration::from_secs(5),
        client.call_tool("scan_url_with_virustotal", test_data::valid_url_params())
    ).await;
    
    assert!(result.is_ok(), "Tool call should complete");
    let tool_result = result.unwrap().unwrap();
    
    let content_str = format!("{:?}", tool_result);
    if content_str.contains("Invalid IP") || content_str.contains("Invalid URL") || content_str.contains("Invalid hash") {
        panic!("Expected success but got validation error: {:?}", tool_result);
    }
    
    assert!(content_str.contains("example.com") || content_str.contains("scan_id") || content_str.contains("Success"));
    
    // Cleanup
    client.cancel();
    server_handle.abort();
}

/// Test hash scanning with VirusTotal - successful case
#[tokio::test]
async fn test_hash_scan_success() {
    let mock_cortex = MockCortexServer::start().await.unwrap();
    let test_server = TestCortexServer::new_with_mock(&mock_cortex).await.unwrap();
    
    let (server_transport, client_transport) = tokio::io::duplex(4096);
    
    // Spawn server
    let server_handle = tokio::spawn(async move {
        test_server.serve(server_transport).await
    });
    
    // Create client and test tool
    let mut client = TestMcpClient::new(client_transport);
    client.initialize().await.unwrap();
    
    let result = timeout(
        Duration::from_secs(5),
        client.call_tool("scan_hash_with_virustotal", test_data::valid_hash_params())
    ).await;
    
    assert!(result.is_ok(), "Tool call should complete");
    let tool_result = result.unwrap().unwrap();
    
    let content_str = format!("{:?}", tool_result);
    if content_str.contains("Invalid IP") || content_str.contains("Invalid URL") || content_str.contains("Invalid hash") {
        panic!("Expected success but got validation error: {:?}", tool_result);
    }
    
    assert!(content_str.contains("sha256") || content_str.contains("positives") || content_str.contains("Success"));
    
    // Cleanup
    client.cancel();
    server_handle.abort();
}

/// Test URL analysis with Urlscan.io - successful case
#[tokio::test]
async fn test_urlscan_analysis_success() {
    let mock_cortex = MockCortexServer::start().await.unwrap();
    let test_server = TestCortexServer::new_with_mock(&mock_cortex).await.unwrap();
    
    let (server_transport, client_transport) = tokio::io::duplex(4096);
    
    // Spawn server
    let server_handle = tokio::spawn(async move {
        test_server.serve(server_transport).await
    });
    
    // Create client and test tool
    let mut client = TestMcpClient::new(client_transport);
    client.initialize().await.unwrap();
    
    let result = timeout(
        Duration::from_secs(5),
        client.call_tool("analyze_url_with_urlscan_io", test_data::valid_url_params())
    ).await;
    
    assert!(result.is_ok(), "Tool call should complete");
    let tool_result = result.unwrap().unwrap();
    
    let content_str = format!("{:?}", tool_result);
    if content_str.contains("Invalid IP") || content_str.contains("Invalid URL") || content_str.contains("Invalid hash") {
        panic!("Expected success but got validation error: {:?}", tool_result);
    }
    
    assert!(content_str.contains("uuid") || content_str.contains("screenshot") || content_str.contains("Success"));
    
    // Cleanup
    client.cancel();
    server_handle.abort();
}

/// Test generic analysis with AbuseFinder - successful case
#[tokio::test]
async fn test_generic_analysis_success() {
    let mock_cortex = MockCortexServer::start().await.unwrap();
    let test_server = TestCortexServer::new_with_mock(&mock_cortex).await.unwrap();
    
    let (server_transport, client_transport) = tokio::io::duplex(4096);
    
    // Spawn server
    let server_handle = tokio::spawn(async move {
        test_server.serve(server_transport).await
    });
    
    // Create client and test tool
    let mut client = TestMcpClient::new(client_transport);
    client.initialize().await.unwrap();
    
    let result = timeout(
        Duration::from_secs(5),
        client.call_tool("analyze_with_abusefinder", test_data::valid_generic_params())
    ).await;
    
    assert!(result.is_ok(), "Tool call should complete");
    let tool_result = result.unwrap().unwrap();
    
    let content_str = format!("{:?}", tool_result);
    if content_str.contains("Invalid IP") || content_str.contains("Invalid URL") || content_str.contains("Invalid hash") {
        panic!("Expected success but got validation error: {:?}", tool_result);
    }
    
    assert!(content_str.contains("query") || content_str.contains("found") || content_str.contains("Success"), "Expected success indicators but got: {}", content_str);
    
    // Cleanup
    client.cancel();
    server_handle.abort();
}

/// Test IP validation - private IP should fail
#[tokio::test]
async fn test_ip_validation_private_ip() {
    let mock_cortex = MockCortexServer::start().await.unwrap();
    let test_server = TestCortexServer::new_with_mock(&mock_cortex).await.unwrap();
    
    let (server_transport, client_transport) = tokio::io::duplex(4096);
    
    // Spawn server
    let server_handle = tokio::spawn(async move {
        test_server.serve(server_transport).await
    });
    
    // Create client and test tool
    let mut client = TestMcpClient::new(client_transport);
    client.initialize().await.unwrap();
    
    let result = timeout(
        Duration::from_secs(5),
        client.call_tool("analyze_ip_with_abuseipdb", test_data::private_ip_params())
    ).await;
    
    assert!(result.is_ok(), "Tool call should complete");
    let tool_result = result.unwrap().unwrap();
    
    let error_str = format!("{:?}", tool_result);
    if !error_str.contains("Invalid IP") {
        panic!("Expected validation error for private IP, but got: {}", error_str);
    }
    
    assert!(error_str.contains("Invalid IP") || error_str.contains("private"));
    
    // Cleanup
    client.cancel();
    server_handle.abort();
}

/// Test URL validation - malicious URL should fail
#[tokio::test]
async fn test_url_validation_malicious_scheme() {
    let mock_cortex = MockCortexServer::start().await.unwrap();
    let test_server = TestCortexServer::new_with_mock(&mock_cortex).await.unwrap();
    
    let (server_transport, client_transport) = tokio::io::duplex(4096);
    
    // Spawn server
    let server_handle = tokio::spawn(async move {
        test_server.serve(server_transport).await
    });
    
    // Create client and test tool
    let mut client = TestMcpClient::new(client_transport);
    client.initialize().await.unwrap();
    
    let result = timeout(
        Duration::from_secs(5),
        client.call_tool("scan_url_with_virustotal", test_data::invalid_url_params())
    ).await;
    
    assert!(result.is_ok(), "Tool call should complete");
    let tool_result = result.unwrap().unwrap();
    
    let error_str = format!("{:?}", tool_result);
    if !error_str.contains("Invalid URL") {
        panic!("Expected validation error for malicious URL, but got: {}", error_str);
    }
    
    assert!(error_str.contains("Invalid URL") || error_str.contains("scheme not allowed"));
    
    // Cleanup
    client.cancel();
    server_handle.abort();
}

/// Test hash validation - invalid hash should fail
#[tokio::test]
async fn test_hash_validation_invalid_format() {
    let mock_cortex = MockCortexServer::start().await.unwrap();
    let test_server = TestCortexServer::new_with_mock(&mock_cortex).await.unwrap();
    
    let (server_transport, client_transport) = tokio::io::duplex(4096);
    
    // Spawn server
    let server_handle = tokio::spawn(async move {
        test_server.serve(server_transport).await
    });
    
    // Create client and test tool
    let mut client = TestMcpClient::new(client_transport);
    client.initialize().await.unwrap();
    
    let result = timeout(
        Duration::from_secs(5),
        client.call_tool("scan_hash_with_virustotal", test_data::invalid_hash_params())
    ).await;
    
    assert!(result.is_ok(), "Tool call should complete");
    let tool_result = result.unwrap().unwrap();
    
    let error_str = format!("{:?}", tool_result);
    if !error_str.contains("Invalid hash") {
        panic!("Expected validation error for invalid hash, but got: {}", error_str);
    }
    
    assert!(error_str.contains("Invalid hash") || error_str.contains("hexadecimal"));
    
    // Cleanup
    client.cancel();
    server_handle.abort();
}

/// Test server creation without environment variables
#[tokio::test]
async fn test_server_creation_without_env_vars() {
    // Save current env vars
    let saved_endpoint = env::var("CORTEX_ENDPOINT").ok();
    let saved_api_key = env::var("CORTEX_API_KEY").ok();
    
    // Clear environment variables
    unsafe {
        let _ = env::remove_var("CORTEX_ENDPOINT");
        let _ = env::remove_var("CORTEX_API_KEY");
    }
    
    // Should fail to create server without proper environment variables
    let result = CortexToolsServer::new();
    assert!(result.is_err(), "Server creation should fail without env vars");
    
    // Restore environment variables
    unsafe {
        if let Some(endpoint) = saved_endpoint {
            env::set_var("CORTEX_ENDPOINT", endpoint);
        } else {
            let _ = env::remove_var("CORTEX_ENDPOINT");
        }
        if let Some(api_key) = saved_api_key {
            env::set_var("CORTEX_API_KEY", api_key);
        } else {
            let _ = env::remove_var("CORTEX_API_KEY");
        }
    }
}

/// Test server creation with environment variables
#[tokio::test]
async fn test_server_creation_with_env_vars() {
    // Save current env vars
    let saved_endpoint = env::var("CORTEX_ENDPOINT").ok();
    let saved_api_key = env::var("CORTEX_API_KEY").ok();
    
    // Set environment variables
    unsafe {
        env::set_var("CORTEX_ENDPOINT", "http://localhost:9000/api");
        env::set_var("CORTEX_API_KEY", "test-api-key");
    }
    
    // Should succeed to create server with proper environment variables
    let result = CortexToolsServer::new();
    assert!(result.is_ok(), "Server creation should succeed with env vars");
    
    // Restore environment variables
    unsafe {
        if let Some(endpoint) = saved_endpoint {
            env::set_var("CORTEX_ENDPOINT", endpoint);
        } else {
            let _ = env::remove_var("CORTEX_ENDPOINT");
        }
        if let Some(api_key) = saved_api_key {
            env::set_var("CORTEX_API_KEY", api_key);
        } else {
            let _ = env::remove_var("CORTEX_API_KEY");
        }
    }
}