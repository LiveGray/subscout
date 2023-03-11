use crate::structs::{Certificate, Subdomain};

use std::thread;
use std::time::Duration;

use indicatif::ProgressBar;
use indicatif::ProgressStyle;

// Scrape subdomains from crt.sh
pub async fn get_crt_domains(domain: &str) -> Result<Vec<Subdomain>, Box<dyn std::error::Error>> {

    println!("[subscout]> Grabbing domains from CrtSH...");

    let certificates: Vec<Certificate> =
        reqwest::get(format!("https://crt.sh/?q={}&output=json", domain))
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
    
        pb.set_message("Scraping CrtSH...");
        thread::sleep(Duration::from_secs(5));

    // Parse response from Crt.sh
    let subdomains: Vec<String> = certificates
        .into_iter()
        .flat_map(|cert| {
            cert.name_value
                .split('\n')
                .map(|dstr| dstr.trim().to_string())
                .collect::<Vec<String>>()
        })
        .filter(|dstr: &String| dstr != domain)
        .filter(|dstr: &String| !dstr.contains('*'))
        .collect();

    let subdomains: Vec<Subdomain> = subdomains
        .into_iter()
        .map(|dstr| Subdomain { url: dstr })
        .collect();

    // Stop progress bar once task completes   
    pb.finish_with_message("done");

    println!("[subscout]> Finished grabbing domains from CrtSH...");

    Ok(subdomains)
}
