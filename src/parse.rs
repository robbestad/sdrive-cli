use lazy_static::lazy_static;
use regex::Regex;

pub fn parse_sdrive_errors(msg: &str) -> String {
    lazy_static! {
        static ref RE: Regex =
            Regex::new(r"(0x[A-Za-z0-9]+)").expect("Failed to compile parse_client_error regex.");
    }

    let mat = RE.find(msg);

    // If there's an RPC error code match in the message, try to parse it, otherwise return the message back.
    match mat {
        Some(m) => {
            let code = msg[m.start()..m.end()].to_string();
            code
        }
        None => msg.to_owned(),
    }
}
