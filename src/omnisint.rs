use crate::structs::Subdomain;

use std::thread;
use std::time::Duration;

use indicatif::ProgressBar;
use indicatif::ProgressStyle;

// get subdomains from omnisint.io
pub async fn get_omnisint_subdomains(
    domain: &str,
) -> Result<Vec<Subdomain>, Box<dyn std::error::Error>> {

    println!("[subscout]> Grabbing domains from OmnisInt...");

    let response: Vec<String> =
        reqwest::get(format!("https://sonar.omnisint.io/subdomains/{}", domain))
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

    pb.set_message("Scraping OmnisInt...");
    thread::sleep(Duration::from_secs(5));

    // Parse response from OmnisInt
    let subdomains: Vec<Subdomain> = response
        .into_iter()
        .map(|sub| Subdomain { url: sub })
        .collect();

    // Stop progress bar once task completes 
    pb.finish_with_message("done");

    println!("[subscout]> Finished grabbing domains from OmnisInt...");

    Ok(subdomains)
}
