//! Windows time types and their ISO-8601 rendering, without a date library.
//!
//! * `FILETIME`: unsigned 64-bit count of 100 ns ticks since 1601-01-01 UTC.
//! * `SYSTEMTIME`: eight little-endian `u16` fields (year, month, weekday, day,
//!   hour, minute, second, milliseconds).
//!
//! Calendar conversion uses Howard Hinnant's `civil_from_days` algorithm
//! (proleptic Gregorian, exact for every representable FILETIME).

use std::fmt::Write as _;

/// Seconds between 1601-01-01 and 1970-01-01.
const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
const TICKS_PER_SEC: u64 = 10_000_000;

/// Fractional-second precision for [`FileTime::write_iso`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Precision {
    /// Six digits; matches how Windows renders `SystemTime` attributes.
    Micros,
    /// Seven digits; the full 100 ns resolution of FILETIME.
    Ticks,
}

/// A raw Windows FILETIME.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FileTime(pub u64);

/// Converts days since 1970-01-01 to a (year, month, day) triple.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

impl FileTime {
    /// Nanoseconds since the Unix epoch (negative before 1970).
    pub fn unix_nanos(self) -> i128 {
        (i128::from(self.0) - i128::from(EPOCH_DIFF_SECS) * i128::from(TICKS_PER_SEC)) * 100
    }

    /// Appends `YYYY-MM-DDTHH:MM:SS.fffffffZ` (or six fractional digits).
    pub fn write_iso(self, out: &mut String, precision: Precision) {
        let secs = (self.0 / TICKS_PER_SEC) as i64 - EPOCH_DIFF_SECS;
        let ticks = self.0 % TICKS_PER_SEC;
        let days = secs.div_euclid(86_400);
        let sod = secs.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        let (h, mi, s) = (sod / 3600, (sod / 60) % 60, sod % 60);
        // Writing into a String cannot fail.
        let _ = write!(out, "{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.");
        let _ = match precision {
            Precision::Micros => write!(out, "{:06}Z", ticks / 10),
            Precision::Ticks => write!(out, "{ticks:07}Z"),
        };
    }

    /// Returns the ISO-8601 rendering as a new string.
    pub fn to_iso(self, precision: Precision) -> String {
        let mut s = String::with_capacity(28);
        self.write_iso(&mut s, precision);
        s
    }
}

/// A raw Windows SYSTEMTIME (fields are not validated; rendering never fails).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SystemTime {
    /// Calendar year.
    pub year: u16,
    /// Month, 1-12.
    pub month: u16,
    /// Day of week, 0 = Sunday (ignored for rendering).
    pub day_of_week: u16,
    /// Day of month.
    pub day: u16,
    /// Hour.
    pub hour: u16,
    /// Minute.
    pub minute: u16,
    /// Second.
    pub second: u16,
    /// Milliseconds.
    pub milliseconds: u16,
}

impl SystemTime {
    /// Decodes the 16-byte little-endian structure.
    pub fn from_bytes(b: &[u8; 16]) -> Self {
        let f = |i: usize| u16::from_le_bytes([b[i * 2], b[i * 2 + 1]]);
        SystemTime {
            year: f(0),
            month: f(1),
            day_of_week: f(2),
            day: f(3),
            hour: f(4),
            minute: f(5),
            second: f(6),
            milliseconds: f(7),
        }
    }

    /// Appends `YYYY-MM-DDTHH:MM:SS.ffffffZ` (milliseconds widened to micros).
    pub fn write_iso(&self, out: &mut String) {
        let _ = write!(
            out,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
            u32::from(self.milliseconds) * 1000
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_epochs() {
        assert_eq!(
            FileTime(0).to_iso(Precision::Micros),
            "1601-01-01T00:00:00.000000Z"
        );
        let unix_epoch = FileTime(116_444_736_000_000_000);
        assert_eq!(unix_epoch.unix_nanos(), 0);
        assert_eq!(
            unix_epoch.to_iso(Precision::Ticks),
            "1970-01-01T00:00:00.0000000Z"
        );
        assert_eq!(FileTime(0).unix_nanos(), -11_644_473_600_000_000_000);
    }

    #[test]
    fn filetime_known_value() {
        // 2016-07-08T18:12:51.6816408Z, the first record of security.evtx.
        let ft = FileTime(131_124_751_716_816_408);
        assert_eq!(ft.to_iso(Precision::Ticks), "2016-07-08T18:12:51.6816408Z");
        assert_eq!(ft.to_iso(Precision::Micros), "2016-07-08T18:12:51.681640Z");
    }

    #[test]
    fn leap_days_and_far_future() {
        // 2000-02-29T00:00:00Z
        let secs = 951_782_400i64 + EPOCH_DIFF_SECS;
        let ft = FileTime(secs as u64 * TICKS_PER_SEC);
        assert_eq!(ft.to_iso(Precision::Micros), "2000-02-29T00:00:00.000000Z");
        // Largest FILETIME renders without panicking (year 60056).
        assert!(
            FileTime(u64::MAX)
                .to_iso(Precision::Ticks)
                .starts_with("60056-")
        );
    }

    #[test]
    fn civil_round_trip_sample() {
        for days in [-719_468i64, -1, 0, 59, 365, 10_957, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert!(
                (1..=12).contains(&m) && (1..=31).contains(&d),
                "{y}-{m}-{d}"
            );
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn systemtime_render() {
        let mut raw = [0u8; 16];
        for (i, v) in [2017u16, 12, 2, 26, 13, 10, 29, 134].iter().enumerate() {
            raw[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
        }
        let st = SystemTime::from_bytes(&raw);
        assert_eq!(st.day_of_week, 2);
        let mut s = String::new();
        st.write_iso(&mut s);
        assert_eq!(s, "2017-12-26T13:10:29.134000Z");
    }
}
