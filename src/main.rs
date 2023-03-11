use itertools::Itertools;
use clap::Parser;
use dotenv::dotenv;

mod alienvault;
mod anubis;
mod crtsh;
mod hackertarget;
mod omnisint;
mod threatminer;

mod structs;
mod utils;
mod files;

#[derive(Parser, Debug)]
#[command(author, version, about)]

pub struct Arguments {

    #[arg(short, long, env("TARGET_URL"),  default_value = "https://hackthissite.org/")]
    pub target_url: String,

    #[arg(short, long, env("OUTPUT_FILE"))]
    pub output_file: Option<String>
}

impl Arguments {
    pub fn from_env_and_args() -> Self{
        dotenv().ok();
        Self::parse()
    }
}

/// Prints the opening title of subscout
fn print_opening() {
    let s = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        r#"  _____       _     _____                 _   "#,
        r#" / ____|     | |   / ____|               | |  "#,
        r#"| (___  _   _| |__| (___   ___ ___  _   _| |_ "#,
        r#" \___ \| | | | '_ \\___ \ / __/ _ \| | | | __|"#,
        r#" ____) | |_| | |_) |___) | (_| (_) | |_| | |_ "#,
        r#"|_____/ \__,_|_.__/_____/ \___\___/ \__,_|\__|"#,
        r#"                                              "#,
        r#"A Simple, Modern Subdomain Enumerator         "#,
    );
    println!("{}", s);
    let info = format!(
        "{}\n{}\n{}\n{}",
        r#"________________________________________"#,
        r#": https://discord.gg/HexRays           :"#,
        r#": https://github.com/dom-sec/subscout  :"#,
        r#" --------------------------------------"#
    );
    println!("{}", info);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    print_opening();

    let start = std::time::Instant::now();

    let raw_target = Arguments::from_env_and_args().target_url; 

    let cleaned_target = utils::sanitize_target_url_string(raw_target);  

    println!("[subscout]> Starting passive subdomain enumeration...");
    println!("[subscout]> Please be patient as this can take a while!\n");

    let (

        alienvault, 
        anubis, 
        crtsh, 
        hackertarget, 
        omnisint, 
        threatminer

        ) = futures::join!(
            
        alienvault::get_alienvault_subdomains(&cleaned_target),
        anubis::get_anubis_subdomains(&cleaned_target),
        crtsh::get_crt_domains(&cleaned_target),
        hackertarget::get_hackertarget_domains(&cleaned_target),
        omnisint::get_omnisint_subdomains(&cleaned_target),
        threatminer::get_threatminer_subdomains(&cleaned_target),
    );

    let duration = start.elapsed();

    let subdomains: Vec<_> = alienvault
        .iter()
        .flatten()
        .chain(anubis.iter().flatten())
        .chain(crtsh.iter().flatten())
        .chain(hackertarget.iter().flatten())
        .chain(omnisint.iter().flatten())
        .chain(threatminer.iter().flatten())
        .unique_by(|s| &s.url)
        .collect();

    let total = subdomains.len();

    let sub_clone = subdomains.clone();

    println!("\n");

    for sub in subdomains.into_iter() {
        println!("{}", sub.url);

    } 

    if let Some(output_file) = Arguments::from_env_and_args().output_file {
        // do something with the output_file argument

        files::create_output_dir()?;

        files::create_output_file(&output_file, &sub_clone)?;
        println!("\n[subscout]> Output successfully writen.");

        println!(
                "\n[subscout]> Successfully scraped {} subdomains from {} in {:?}",
                total, cleaned_target, duration
            );

    } else {

    println!(
        "\n[subscout]> Successfully scraped {} subdomains from {} in {:?}",
        total, cleaned_target, duration
    );
};
    Ok(())
}
