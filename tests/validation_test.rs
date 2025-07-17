//! Simple validation tests to verify validation logic works correctly

use std::env;
use mcp_server_cortex::CortexToolsServer;
use rmcp::handler::server::tool::Parameters;

#[tokio::test]
async fn test_ip_validation_directly() {
    // Save current env vars
    let saved_endpoint = env::var("CORTEX_ENDPOINT").ok();
    let saved_api_key = env::var("CORTEX_API_KEY").ok();
    
    // Set up environment
    unsafe {
        env::set_var("CORTEX_ENDPOINT", "http://localhost:9999/api");
        env::set_var("CORTEX_API_KEY", "test-key");
    }
    
    let server = CortexToolsServer::new().unwrap();
    
    // Test private IP validation
    let private_ip_params = mcp_server_cortex::tools::ip::AnalyzeIpParams {
        ip: "192.168.1.1".to_string(),
        analyzer_name: None,
        max_retries: Some(1),
    };
    
    let result = mcp_server_cortex::tools::ip::analyze_ip_with_abuseipdb(
        &server, 
        Parameters(private_ip_params)
    ).await;
    
    assert!(result.is_ok());
    let tool_result = result.unwrap();
    let result_str = format!("{:?}", tool_result);
    
    // Should contain validation error
    assert!(result_str.contains("Invalid IP") || result_str.contains("private"), 
            "Expected validation error but got: {}", result_str);
    
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

#[tokio::test]
async fn test_url_validation_directly() {
    // Save current env vars
    let saved_endpoint = env::var("CORTEX_ENDPOINT").ok();
    let saved_api_key = env::var("CORTEX_API_KEY").ok();
    
    // Set up environment
    unsafe {
        env::set_var("CORTEX_ENDPOINT", "http://localhost:9999/api");
        env::set_var("CORTEX_API_KEY", "test-key");
    }
    
    let server = CortexToolsServer::new().unwrap();
    
    // Test malicious URL validation
    let malicious_url_params = mcp_server_cortex::tools::url::ScanUrlWithVirusTotalParams {
        url: "javascript:alert('xss')".to_string(),
        analyzer_name: None,
        max_retries: Some(1),
    };
    
    let result = mcp_server_cortex::tools::url::scan_url_with_virustotal(
        &server, 
        Parameters(malicious_url_params)
    ).await;
    
    assert!(result.is_ok());
    let tool_result = result.unwrap();
    let result_str = format!("{:?}", tool_result);
    
    // Should contain validation error
    assert!(result_str.contains("Invalid URL") || result_str.contains("scheme not allowed"), 
            "Expected validation error but got: {}", result_str);
    
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

#[tokio::test]
async fn test_hash_validation_directly() {
    // Save current env vars
    let saved_endpoint = env::var("CORTEX_ENDPOINT").ok();
    let saved_api_key = env::var("CORTEX_API_KEY").ok();
    
    // Set up environment
    unsafe {
        env::set_var("CORTEX_ENDPOINT", "http://localhost:9999/api");
        env::set_var("CORTEX_API_KEY", "test-key");
    }
    
    let server = CortexToolsServer::new().unwrap();
    
    // Test invalid hash validation
    let invalid_hash_params = mcp_server_cortex::tools::hash::ScanHashWithVirusTotalParams {
        hash: "invalid-hash".to_string(),
        analyzer_name: None,
        max_retries: Some(1),
    };
    
    let result = mcp_server_cortex::tools::hash::scan_hash_with_virustotal(
        &server, 
        Parameters(invalid_hash_params)
    ).await;
    
    assert!(result.is_ok());
    let tool_result = result.unwrap();
    let result_str = format!("{:?}", tool_result);
    
    // Should contain validation error
    assert!(result_str.contains("Invalid hash") || result_str.contains("hexadecimal"), 
            "Expected validation error but got: {}", result_str);
    
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