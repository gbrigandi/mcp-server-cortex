///
/// This module provides helper functions for interacting with the Cortex API.
///
use cortex_client::apis::configuration::Configuration;
use rmcp::{ErrorData, model::*};
use serde_json::json;
use std::env;

pub fn setup_cortex_configuration() -> Result<Configuration, String> {
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

pub async fn run_analyzer_and_get_report(
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
            Ok(CallToolResult::success(vec![
                Content::json(success_content)
                    .map_err(|e| ErrorData::internal_error(e.to_string(), None))?,
            ]))
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
    tracing::debug!(analyzer = %analyzer_name_to_find, "Looking up analyzer ID");

    let find_request = Some(cortex_client::models::AnalyzerFindRequest::default());
    let analyzer_instances =
        cortex_client::apis::analyzer_api::find_analyzers(config, find_request).await?;

    tracing::debug!(count = %analyzer_instances.len(), "Found analyzer instances");

    for analyzer_instance in analyzer_instances {
        if let Some(name) = &analyzer_instance.name {
            if name == analyzer_name_to_find {
                if let Some(id) = analyzer_instance._id {
                    tracing::debug!(
                        analyzer = %analyzer_name_to_find,
                        id = %id,
                        "Found analyzer"
                    );
                    return Ok(Some(id));
                }
            }
        }
    }

    tracing::warn!(analyzer = %analyzer_name_to_find, "Analyzer not found");
    Ok(None)
}

async fn run_job_and_wait_for_report(
    config: &Configuration,
    analyzer_worker_id: &str,
    job_request: cortex_client::models::JobCreateRequest,
    analyzer_name_for_log: &str,
    observable_for_log: &str,
    max_retries: usize,
) -> Result<cortex_client::models::JobReportResponse, Box<dyn std::error::Error>> {
    use cortex_client::apis::job_api;
    use std::time::Duration;

    tracing::debug!(
        analyzer = %analyzer_name_for_log,
        observable = %observable_for_log,
        worker_id = %analyzer_worker_id,
        "Creating analyzer job"
    );

    let job_response =
        job_api::create_analyzer_job(config, analyzer_worker_id, job_request).await?;
    let job_id = job_response._id.ok_or("No job ID returned")?;

    tracing::info!(
        job_id = %job_id,
        analyzer = %analyzer_name_for_log,
        observable = %observable_for_log,
        max_retries = %max_retries,
        "Job created, polling for completion"
    );

    for attempt in 1..=max_retries {
        let job_details = job_api::get_job_by_id(config, &job_id).await?;
        let status_str = match &job_details.status {
            Some(s) => format!("{:?}", s),
            None => "Unknown".to_string(),
        };

        tracing::debug!(
            job_id = %job_id,
            attempt = %attempt,
            max_retries = %max_retries,
            status = %status_str,
            "Polling job status"
        );

        match job_details.status {
            Some(cortex_client::models::job::Status::Success) => {
                tracing::info!(
                    job_id = %job_id,
                    analyzer = %analyzer_name_for_log,
                    observable = %observable_for_log,
                    attempts = %attempt,
                    "Job completed successfully"
                );
                return Ok(job_api::get_job_report(config, &job_id).await?);
            }
            Some(cortex_client::models::job::Status::Failure) => {
                let err_msg = format!("Job failed: {:?}", job_details.error_message);
                tracing::error!(
                    job_id = %job_id,
                    analyzer = %analyzer_name_for_log,
                    error = ?job_details.error_message,
                    "Job failed"
                );
                return Err(err_msg.into());
            }
            _ => {
                if attempt < max_retries {
                    tracing::debug!(
                        job_id = %job_id,
                        attempt = %attempt,
                        "Job still running, waiting 30 seconds..."
                    );
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            }
        }
    }

    tracing::error!(
        job_id = %job_id,
        analyzer = %analyzer_name_for_log,
        observable = %observable_for_log,
        max_retries = %max_retries,
        "Job did not complete in time"
    );
    Err("Job did not complete in time.".into())
}

