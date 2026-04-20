fn main() {
    let body = r#"{"requestId":"req_rust_demo","resourceId":"premium:api","operation":"premium:api","tokenOrUuid":"rust-agent","priceMinor":5}"#;

    println!("POST https://tdm.todealmarket.com/authorize");
    println!("Content-Type: application/json");
    println!("X-TDM-Session-Token: tdm_session_replace_me");
    println!();
    println!("{}", body);
    println!();
    println!("Use reqwest or hyper to send this exact body.");
}

