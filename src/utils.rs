// Remove beginning protocols from the target url
pub fn sanitize_target_url_string(raw_target: String) -> String {
    raw_target
        .replace("www.", "")
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "")
        .replace("https://www.", "")
}