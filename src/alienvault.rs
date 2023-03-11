use crate::structs::{AlientVaultDNS, Subdomain};

use std::thread;
use std::time::Duration;

use indicatif::ProgressBar;
use indicatif::ProgressStyle;

// Scrape subdomains from alienvault
pub async fn get_alienvault_subdomains(
    domain: &str,
) -> Result<Vec<Subdomain>, Box<dyn std::error::Error>> {

    println!("[subscout]> Grabbing domains from AlienVault...");

    let results: AlientVaultDNS = reqwest::get(format!(
        "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
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

    pb.set_message("Scraping Alienvault...");
    thread::sleep(Duration::from_secs(5));

    // Parse response from AlienVault
    let subdomains: Vec<Subdomain> = results
        .passive_dns
        .into_iter()
        .filter(|sub| sub.hostname.is_some())
        .map(|sub| Subdomain {
            url: sub.hostname.unwrap(),
        })
        .collect();

    // Stop progress bar once task completes    
    pb.finish_with_message("done");

    println!("[subscout]> Finished grabbing domains from AlienVault...");

    Ok(subdomains)
   
}

