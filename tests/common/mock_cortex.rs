//! Mock Cortex server implementation for testing

use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use http_body_util::{BodyExt, Full};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct MockCortexServer {
    pub base_url: String,
    pub port: u16,
    analyzers: Arc<RwLock<HashMap<String, AnalyzerInfo>>>,
    jobs: Arc<RwLock<HashMap<String, JobInfo>>>,
    cancellation_token: CancellationToken,
}

#[derive(Clone, Debug)]
pub struct AnalyzerInfo {
    pub id: String,
    pub name: String,
    pub description: String,
}

#[derive(Clone, Debug)]
pub struct JobInfo {
    pub id: String,
    pub analyzer_id: String,
    pub status: String,
    pub data: String,
    pub data_type: String,
    pub report: Option<Value>,
    pub error_message: Option<String>,
}

impl MockCortexServer {
    pub async fn start() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let base_url = format!("http://127.0.0.1:{}", port);
        
        let analyzers = Arc::new(RwLock::new(HashMap::new()));
        let jobs = Arc::new(RwLock::new(HashMap::new()));
        let cancellation_token = CancellationToken::new();
        
        let server = MockCortexServer {
            base_url: base_url.clone(),
            port,
            analyzers: analyzers.clone(),
            jobs: jobs.clone(),
            cancellation_token: cancellation_token.clone(),
        };
        
        // Add default analyzers
        server.add_default_analyzers().await;
        
        // Start the server
        let server_clone = server.clone();
        tokio::spawn(async move {
            server_clone.run(listener).await
        });
        
        // Give the server a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        
        Ok(server)
    }
    
    async fn add_default_analyzers(&self) {
        let mut analyzers = self.analyzers.write().await;
        
        analyzers.insert("abuseipdb_1".to_string(), AnalyzerInfo {
            id: "abuseipdb_1".to_string(),
            name: "AbuseIPDB_1_0".to_string(),
            description: "AbuseIPDB IP reputation analyzer".to_string(),
        });
        
        analyzers.insert("virustotal_scan_1".to_string(), AnalyzerInfo {
            id: "virustotal_scan_1".to_string(),
            name: "VirusTotal_Scan_3_1".to_string(),
            description: "VirusTotal URL/File scanner".to_string(),
        });
        
        analyzers.insert("virustotal_report_1".to_string(), AnalyzerInfo {
            id: "virustotal_report_1".to_string(),
            name: "VirusTotal_GetReport_3_1".to_string(),
            description: "VirusTotal hash report analyzer".to_string(),
        });
        
        analyzers.insert("urlscan_io_1".to_string(), AnalyzerInfo {
            id: "urlscan_io_1".to_string(),
            name: "Urlscan_io_Scan_0_1_0".to_string(),
            description: "Urlscan.io URL analyzer".to_string(),
        });
        
        analyzers.insert("abuse_finder_1".to_string(), AnalyzerInfo {
            id: "abuse_finder_1".to_string(),
            name: "Abuse_Finder_3_0".to_string(),
            description: "Abuse Finder generic analyzer".to_string(),
        });
    }
    
    async fn run(self, listener: TcpListener) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            tokio::select! {
                _ = self.cancellation_token.cancelled() => {
                    break;
                }
                result = listener.accept() => {
                    let (stream, _) = result?;
                    let io = TokioIo::new(stream);
                    let server = self.clone();
                    
                    tokio::spawn(async move {
                        if let Err(err) = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service_fn(move |req| {
                                let server = server.clone();
                                async move { server.handle_request(req).await }
                            }))
                            .await
                        {
                            eprintln!("Error serving connection: {:?}", err);
                        }
                    });
                }
            }
        }
        Ok(())
    }
    
    async fn handle_request(&self, req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("");
        
        tracing::info!("Mock Cortex: {} {} {}", method, path, query);
        
        let response = match (method.clone(), path.as_str()) {
            (Method::GET, "/api/analyzer") => self.list_analyzers().await,
            (Method::POST, "/api/analyzer/_search") => self.list_analyzers().await,
            (Method::POST, "/api/analyzer/_find") => self.list_analyzers().await,
            (Method::POST, path) if path.starts_with("/api/analyzer/") && path.ends_with("/run") => {
                let analyzer_id = path.split('/').nth(3).unwrap_or("").to_string();
                tracing::info!("Creating job for analyzer ID: {}", analyzer_id);
                let body = req.collect().await.unwrap().to_bytes();
                self.create_job(analyzer_id, body).await
            }
            (Method::GET, path) if path.starts_with("/api/job/") && !path.ends_with("/report") => {
                let job_id = path.split('/').nth(3).unwrap_or("").to_string();
                self.get_job(job_id).await
            }
            (Method::GET, path) if path.starts_with("/api/job/") && path.ends_with("/report") => {
                let job_id = path.split('/').nth(3).unwrap_or("").to_string();
                self.get_job_report(job_id).await
            }
            _ => {
                tracing::warn!("Mock Cortex: Unhandled request {} {} {}", method, path, query);
                Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::from("Not Found")))
                    .unwrap())
            }
        };
        
        Ok(response.unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("Internal Server Error")))
                .unwrap()
        }))
    }
    
    async fn list_analyzers(&self) -> Result<Response<Full<Bytes>>, ()> {
        let analyzers = self.analyzers.read().await;
        let analyzer_list: Vec<Value> = analyzers.values().map(|a| json!({
            "_id": a.id,
            "name": a.name,
            "description": a.description
        })).collect();
        
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(serde_json::to_string(&analyzer_list).unwrap())))
            .unwrap();
        
        Ok(response)
    }
    
    async fn create_job(&self, analyzer_id: String, body: Bytes) -> Result<Response<Full<Bytes>>, ()> {
        let job_request: Value = serde_json::from_slice(&body).map_err(|_| ())?;
        
        let job_id = format!("job_{}", uuid::Uuid::new_v4().to_string().replace('-', "")[..8].to_string());
        let data = job_request.get("data").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let data_type = job_request.get("dataType").and_then(|v| v.as_str()).unwrap_or("").to_string();
        
        let job_info = JobInfo {
            id: job_id.clone(),
            analyzer_id: analyzer_id.clone(),
            status: "Success".to_string(), // Simulate immediate success for testing
            data,
            data_type,
            report: Some(self.generate_mock_report(&analyzer_id, &job_request).await),
            error_message: None,
        };
        
        self.jobs.write().await.insert(job_id.clone(), job_info);
        
        let response = json!({
            "_id": job_id,
            "status": "Success"
        });
        
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(serde_json::to_string(&response).unwrap())))
            .unwrap())
    }
    
    async fn get_job(&self, job_id: String) -> Result<Response<Full<Bytes>>, ()> {
        let jobs = self.jobs.read().await;
        if let Some(job) = jobs.get(&job_id) {
            let response = json!({
                "_id": job.id,
                "status": job.status,
                "errorMessage": job.error_message
            });
            
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(serde_json::to_string(&response).unwrap())))
                .unwrap())
        } else {
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Job not found")))
                .unwrap())
        }
    }
    
    async fn get_job_report(&self, job_id: String) -> Result<Response<Full<Bytes>>, ()> {
        let jobs = self.jobs.read().await;
        if let Some(job) = jobs.get(&job_id) {
            if let Some(report) = &job.report {
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(serde_json::to_string(report).unwrap())))
                    .unwrap())
            } else {
                Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::from("Report not available")))
                    .unwrap())
            }
        } else {
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Job not found")))
                .unwrap())
        }
    }
    
    async fn generate_mock_report(&self, analyzer_id: &str, job_request: &Value) -> Value {
        let data = job_request.get("data").and_then(|v| v.as_str()).unwrap_or("");
        let data_type = job_request.get("dataType").and_then(|v| v.as_str()).unwrap_or("");
        
        match analyzer_id {
            "abuseipdb_1" => json!({
                "summary": {
                    "taxonomies": [{
                        "level": "info",
                        "namespace": "AbuseIPDB",
                        "predicate": "Malicious",
                        "value": "0%"
                    }]
                },
                "full": {
                    "abuseConfidencePercentage": 0,
                    "ipAddress": data,
                    "isPublic": true,
                    "ipVersion": 4,
                    "isWhitelisted": false,
                    "countryCode": "US",
                    "usageType": "Data Center/Web Hosting/Transit",
                    "totalReports": 0,
                    "numDistinctUsers": 0
                }
            }),
            "virustotal_scan_1" => json!({
                "summary": {
                    "taxonomies": [{
                        "level": "info",
                        "namespace": "VirusTotal",
                        "predicate": "Detection",
                        "value": "0/70"
                    }]
                },
                "full": {
                    "url": data,
                    "scan_id": "test-scan-id",
                    "permalink": "https://www.virustotal.com/gui/url/test-scan-id",
                    "positives": 0,
                    "total": 70,
                    "scan_date": "2024-01-01 12:00:00"
                }
            }),
            "virustotal_report_1" => json!({
                "summary": {
                    "taxonomies": [{
                        "level": "info",
                        "namespace": "VirusTotal",
                        "predicate": "Detection",
                        "value": "0/70"
                    }]
                },
                "full": {
                    "sha256": data,
                    "positives": 0,
                    "total": 70,
                    "scan_date": "2024-01-01 12:00:00",
                    "permalink": "https://www.virustotal.com/gui/file/test-file-id"
                }
            }),
            "urlscan_io_1" => json!({
                "summary": {
                    "taxonomies": [{
                        "level": "info",
                        "namespace": "URLScan",
                        "predicate": "Malicious",
                        "value": "0"
                    }]
                },
                "full": {
                    "url": data,
                    "uuid": "test-uuid",
                    "result": "https://urlscan.io/result/test-uuid",
                    "screenshot": "https://urlscan.io/screenshots/test-uuid.png",
                    "verdicts": {
                        "overall": {
                            "malicious": false,
                            "score": 0
                        }
                    }
                }
            }),
            "abuse_finder_1" => json!({
                "summary": {
                    "taxonomies": [{
                        "level": "info",
                        "namespace": "AbuseFinder",
                        "predicate": "Found",
                        "value": "0"
                    }]
                },
                "full": {
                    "query": data,
                    "query_type": data_type,
                    "found": false,
                    "results": []
                }
            }),
            _ => json!({
                "summary": {
                    "taxonomies": [{
                        "level": "info",
                        "namespace": "Unknown",
                        "predicate": "Result",
                        "value": "unknown"
                    }]
                },
                "full": {
                    "data": data,
                    "message": "Mock analyzer result"
                }
            })
        }
    }
    
    pub async fn add_failing_analyzer(&self, analyzer_name: &str) {
        let mut analyzers = self.analyzers.write().await;
        analyzers.insert(format!("failing_{}", analyzer_name), AnalyzerInfo {
            id: format!("failing_{}", analyzer_name),
            name: analyzer_name.to_string(),
            description: format!("Failing test analyzer for {}", analyzer_name),
        });
    }
    
    pub async fn simulate_job_failure(&self, job_id: &str, error_message: &str) {
        let mut jobs = self.jobs.write().await;
        if let Some(job) = jobs.get_mut(job_id) {
            job.status = "Failure".to_string();
            job.error_message = Some(error_message.to_string());
            job.report = None;
        }
    }
    
    pub fn shutdown(&self) {
        self.cancellation_token.cancel();
    }
}

impl Drop for MockCortexServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// Simple UUID generation for testing
mod uuid {
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    pub struct Uuid;
    
    impl Uuid {
        pub fn new_v4() -> Self {
            Self
        }
        
        pub fn to_string(&self) -> String {
            let mut hasher = DefaultHasher::new();
            let time = SystemTime::now().duration_since(UNIX_EPOCH)
                .unwrap_or_default().as_nanos();
            time.hash(&mut hasher);
            let hash = hasher.finish();
            format!("{:x}", hash)
        }
    }
}