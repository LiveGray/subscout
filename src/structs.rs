extern crate serde;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Certificate {
    pub issuer_ca_id: u32,
    pub issuer_name: String,
    pub common_name: String,
    pub name_value: String,
    pub id: u64,
    pub serial_number: String,
}

#[derive(Debug, Deserialize)]
pub struct DNSEntry {
    pub address: Option<String>,
    pub hostname: Option<String>,
    pub record_type: Option<String>,
    pub asset_type: Option<String>,
    pub asn: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AlientVaultDNS {
    pub passive_dns: Vec<DNSEntry>,
    pub count: u64,
}

#[derive(Debug, Deserialize)]
pub struct ThreatminerResults {
    pub status_code: String,
    pub status_message: String,
    pub results: Vec<String>,
}

#[derive(Debug)]
pub struct Subdomain {
    pub url: String,
}
