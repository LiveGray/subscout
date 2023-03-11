use crate::structs::{Subdomain, ThreatminerResults};

use std::thread;
use std::time::Duration;

use indicatif::ProgressBar;
use indicatif::ProgressStyle;

// get subdomains from threatminer
pub async fn get_threatminer_subdomains(
    domain: &str,
) -> Result<Vec<Subdomain>, Box<dyn std::error::Error>> {

    println!("[subscout]> Grabbing domains from ThreatMiner...");

    let response: ThreatminerResults = reqwest::get(format!(
        "https://api.threatminer.org/v2/domain.php?q={}&rt=5",
        domain
    ))
    .await?
    .json()
    .await?;

    // Generate progress bar
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(120));
    pb.set_style(
        ProgressStyle::with_template("{spinner:.blue} {msg}")
            .unwrap()
            .tick_strings(&[
                "▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹",
                "▸▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹",
                "▹▸▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹",
                "▹▹▸▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹",
                "▹▹▹▸▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹",
                "▹▹▹▹▸▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹",
                "▹▹▹▹▹▸▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹",
                "▹▹▹▹▹▹▸▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹",
                "▹▹▹▹▹▹▹▸▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹",
                "▹▹▹▹▹▹▹▹▸▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹",
                "▹▹▹▹▹▹▹▹▹▸▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹",
                "▹▹▹▹▹▹▹▹▹▹▸▹▹▹▹▹▹▹▹▹▹▹▹▹▹",
                "▹▹▹▹▹▹▹▹▹▹▹▸▹▹▹▹▹▹▹▹▹▹▹▹▹",
                "▹▹▹▹▹▹▹▹▹▹▹▹▸▹▹▹▹▹▹▹▹▹▹▹▹",
                "▹▹▹▹▹▹▹▹▹▹▹▹▹▸▹▹▹▹▹▹▹▹▹▹▹",
                "▹▹▹▹▹▹▹▹▹▹▹▹▹▹▸▹▹▹▹▹▹▹▹▹▹",
                "▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▸▹▹▹▹▹▹▹▹▹",
                "▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▸▹▹▹▹▹▹▹▹",
                "▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▸▹▹▹▹▹▹▹",
                "▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▸▹▹▹▹▹▹",
                "▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▸▹▹▹▹▹",
                "▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▸▹▹▹▹",
                "▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▸▹▹▹",
                "▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▸▹▹",
                "▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▸▹",
                "▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▹▸",
                "▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪",
            ]),
    );

    pb.set_message("Scraping ThreatMiner...");
    thread::sleep(Duration::from_secs(5));

    // Parse response from AlienVault
    let subdomains: Vec<Subdomain> = response
        .results
        .into_iter()
        .map(|sub| Subdomain { url: sub })
        .collect();

    // Stop progress bar once task completes   
    pb.finish_with_message("done");

    println!("[subscout]> Finished grabbing domains from ThreatMiner...");

    Ok(subdomains)
}
