use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

use crate::structs::Subdomain;

pub fn create_output_dir() -> Result<(), std::io::Error> {
    let dir_name = "output";
    match fs::metadata(dir_name) {
        Ok(metadata) => {
            if metadata.is_dir() {
                // Output directory already exists
                Ok(())
            } else {
                // Output directory is a file, not a directory
                Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "A file with the name 'output' already exists",
                ))
            }
        }
        Err(_error) => {
            // Output directory doesn't exist, so create it
            fs::create_dir(dir_name)?;
            Ok(())
        }
    }
}

pub fn create_output_file(output_file: &str, subdomains: &Vec<&Subdomain>) -> std::io::Result<()> {
    let dir_name = "output";
    let dir_path = Path::new(dir_name);
    if !dir_path.exists() {
        fs::create_dir(dir_name)?;
    }

    let file_path = PathBuf::from(dir_path).join(output_file);
    let mut file_exists = file_path.exists();
    let mut new_file_path = file_path.clone();

    // Check if the file already exists
    while file_exists {
        println!("File already exists. Please enter a new filename:");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        new_file_path = PathBuf::from(dir_path).join(input.trim().to_string() + ".txt");
        file_exists = new_file_path.exists();
    }

    // Create the new file
    let mut file = File::create(&new_file_path)?;
    for subdomain in subdomains.iter() {
        writeln!(file, "{}", subdomain.url)?;
    }

    Ok(())
}
