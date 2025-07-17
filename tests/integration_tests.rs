//! Integration tests for the MCP Cortex Server
//!
//! These tests verify the full MCP server-client communication flow,
//! including tool invocations, validation, and error handling.

use std::env;
use mcp_server_cortex::CortexToolsServer;
use tokio::time::{timeout, Duration};
use std::sync::Mutex;
use serde_json::json;

// Mutex to ensure environment variable tests don't run concurrently
static ENV_LOCK: Mutex<()> = Mutex::new(());

mod common;
use common::{MockCortexServer, TestCortexServer, TestMcpClient, test_data};

/// Test the basic MCP server initialization and tool listing
#[tokio::test]
async fn test_server_initialization() {
    let _guard = ENV_LOCK.lock().unwrap();
    
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
    let _guard = ENV_LOCK.lock().unwrap();
    
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
    let _guard = ENV_LOCK.lock().unwrap();
    
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
    let _guard = ENV_LOCK.lock().unwrap();
    
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
    let _guard = ENV_LOCK.lock().unwrap();
    
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
    let _guard = ENV_LOCK.lock().unwrap();
    
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
    let _guard = ENV_LOCK.lock().unwrap();
    
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
    let _guard = ENV_LOCK.lock().unwrap();
    
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
    let _guard = ENV_LOCK.lock().unwrap();
    
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
    let _guard = ENV_LOCK.lock().unwrap();
    
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
    let _guard = ENV_LOCK.lock().unwrap();
    
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

/// Test that the SOC analyst prompt is properly serviced
#[tokio::test]
async fn test_soc_analyst_prompt() {
    let _guard = ENV_LOCK.lock().unwrap();
    
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
    
    // Test list_prompts
    let list_response = timeout(Duration::from_secs(5), client.list_prompts()).await;
    assert!(list_response.is_ok(), "list_prompts request should succeed");
    
    let list_result = list_response.unwrap().unwrap();
    assert!(list_result.get("result").is_some(), "Response should have result field");
    
    let prompts = list_result["result"]["prompts"].as_array().unwrap();
    assert_eq!(prompts.len(), 1, "Should have exactly one prompt");
    
    let prompt = &prompts[0];
    assert_eq!(prompt["name"], "soc_analyst", "Prompt name should be 'soc_analyst'");
    assert!(prompt["description"].is_string(), "Prompt should have a description");
    assert!(prompt["arguments"].is_array(), "Prompt should have arguments");
    
    let arguments = prompt["arguments"].as_array().unwrap();
    assert_eq!(arguments.len(), 1, "Should have exactly one argument");
    assert_eq!(arguments[0]["name"], "incident_context", "Argument name should be 'incident_context'");
    assert_eq!(arguments[0]["required"], false, "Argument should be optional");
    
    // Test get_prompt without incident_context
    let get_response = timeout(Duration::from_secs(5), client.get_prompt("soc_analyst", None)).await;
    assert!(get_response.is_ok(), "get_prompt request should succeed");
    
    let get_result = get_response.unwrap().unwrap();
    assert!(get_result.get("result").is_some(), "Response should have result field");
    
    let messages = get_result["result"]["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1, "Should have exactly one message");
    
    let message = &messages[0];
    assert_eq!(message["role"], "user", "Message role should be user");
    assert!(message["content"]["text"].is_string(), "Message should have text content");
    
    let text = message["content"]["text"].as_str().unwrap();
    
    // Validate that the prompt contains the expected SOC analyst content
    assert!(text.contains("SOC analyst"), "Prompt should contain 'SOC analyst'");
    assert!(text.contains("8+ years experience"), "Prompt should mention experience level");
    assert!(text.contains("cybersecurity incident response"), "Prompt should mention cybersecurity");
    assert!(text.contains("threat intelligence analysis"), "Prompt should mention threat intelligence");
    assert!(text.contains("Cortex"), "Prompt should mention Cortex");
    
    // Validate that it mentions the available tools
    assert!(text.contains("analyze_ip_with_abuseipdb"), "Prompt should mention IP analysis tool");
    assert!(text.contains("scan_url_with_virustotal"), "Prompt should mention URL scanning tool");
    assert!(text.contains("scan_hash_with_virustotal"), "Prompt should mention hash scanning tool");
    assert!(text.contains("analyze_with_abusefinder"), "Prompt should mention AbuseFinder tool");
    
    // Validate key methodology elements
    assert!(text.contains("MITRE ATT&CK"), "Prompt should mention MITRE ATT&CK");
    assert!(text.contains("TTPs"), "Prompt should mention TTPs");
    assert!(text.contains("threat severity"), "Prompt should mention threat severity");
    assert!(text.contains("false positives"), "Prompt should mention reducing false positives");
    
    // Validate analysis framework
    assert!(text.contains("Analysis Framework"), "Prompt should contain analysis framework");
    assert!(text.contains("Assess severity and impact"), "Prompt should mention severity assessment");
    assert!(text.contains("Identify observables"), "Prompt should mention observable identification");
    assert!(text.contains("Correlate threat intel"), "Prompt should mention threat intel correlation");
    
    // Validate tool recommendations
    assert!(text.contains("Cortex Recommendations"), "Prompt should contain tool recommendations");
    assert!(text.contains("IPs: Use analyze_ip_with_abuseipdb"), "Prompt should have IP recommendations");
    assert!(text.contains("Domains/URLs: Use scan_url_with_virustotal or analyze_with_abusefinder"), "Prompt should have URL recommendations");
    assert!(text.contains("File Hashes: Use scan_hash_with_virustotal"), "Prompt should have hash recommendations");
    
    // Validate communication guidance
    assert!(text.contains("Always mask hostnames"), "Prompt should mention masking PII");
    assert!(text.contains("[MASKED-IP-XX.XX.XX.XX]"), "Prompt should show masking format");
    
    // Validate default context
    assert!(text.contains("No specific incident context provided"), "Default context should be used");
    
    // Test get_prompt with incident_context
    let context_args = json!({
        "incident_context": "Suspicious IP 192.168.1.100 detected in logs"
    });
    
    let get_context_response = timeout(Duration::from_secs(5), client.get_prompt("soc_analyst", Some(context_args))).await;
    assert!(get_context_response.is_ok(), "get_prompt with context should succeed");
    
    let get_context_result = get_context_response.unwrap().unwrap();
    let context_messages = get_context_result["result"]["messages"].as_array().unwrap();
    let context_text = context_messages[0]["content"]["text"].as_str().unwrap();
    
    assert!(context_text.contains("Suspicious IP 192.168.1.100 detected in logs"), "Custom context should be included");
    // Should still contain all the core SOC analyst elements
    assert!(context_text.contains("SOC analyst"), "Prompt should still contain 'SOC analyst'");
    assert!(context_text.contains("analyze_ip_with_abuseipdb"), "Prompt should still mention analysis tools");
    assert!(!context_text.contains("analyze_url_with_urlscan_io"), "Prompt should not mention URLScan.io tool");
    
    // Test get_prompt with invalid prompt name
    let invalid_response = timeout(Duration::from_secs(5), client.get_prompt("invalid_prompt", None)).await;
    assert!(invalid_response.is_ok(), "Invalid prompt request should complete");
    
    let invalid_result = invalid_response.unwrap().unwrap();
    assert!(invalid_result.get("error").is_some(), "Invalid prompt should return error");
    
    // Cleanup
    client.cancel();
    server_handle.abort();
}