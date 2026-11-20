//! Lifetimes offered for the tokens the proxy issues.

use time::{Duration, OffsetDateTime};

/// Every lifetime a token can have, in days; no other is accepted.
pub(crate) const TOKEN_LIFETIMES_DAYS: [u16; 4] = [1, 7, 30, 90];

/// The lifetime forms preselect, in days.
pub(crate) const DEFAULT_TOKEN_LIFETIME_DAYS: u16 = 30;

/// Returns when a token issued at `now` with a lifetime of `days` expires, if `days` is an offered lifetime.
pub(crate) fn token_expiry(days: u16, now: OffsetDateTime) -> Option<OffsetDateTime> {
    TOKEN_LIFETIMES_DAYS
        .contains(&days)
        .then(|| now + Duration::days(i64::from(days)))
}

/// A lifetime as shown in forms, e.g. `1 day` or `30 days`.
pub(crate) fn lifetime_label(days: u16) -> String {
    if days == 1 {
        "1 day".to_owned()
    } else {
        format!("{days} days")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_offered_lifetimes_are_accepted() {
        let now = OffsetDateTime::now_utc();

        for days in TOKEN_LIFETIMES_DAYS {
            assert_eq!(token_expiry(days, now), Some(now + Duration::days(i64::from(days))));
        }
        for days in [0, 2, 14, 365] {
            assert_eq!(token_expiry(days, now), None, "{days}");
        }
        assert!(TOKEN_LIFETIMES_DAYS.contains(&DEFAULT_TOKEN_LIFETIME_DAYS));
    }

    #[test]
    fn labels() {
        assert_eq!(lifetime_label(1), "1 day");
        assert_eq!(lifetime_label(90), "90 days");
    }
}
