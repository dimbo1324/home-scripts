pub mod checksum;
pub mod code_shape;
pub mod credentials;
pub mod entropy;
pub mod keyword;
pub(crate) mod keyword_scan;
pub mod prefilter;
pub mod provider;
pub mod risky_code;
pub(crate) mod token_scan;

pub(crate) fn confidence_rank(level: &str) -> u8 {
    match level {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rank_orders_critical_first() {
        let mut levels = vec!["low", "critical", "medium", "high"];
        levels.sort_by_key(|level| confidence_rank(level));
        assert_eq!(levels, vec!["critical", "high", "medium", "low"]);
    }
}
