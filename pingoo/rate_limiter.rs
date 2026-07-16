use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use rules::RateLimit;
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tokio::time::Instant;
use tracing::error;

use crate::services::http_utils::new_internal_error_response_500;
use crate::services::http_utils::new_service_unavailable_error_503;
use crate::services::http_utils::new_too_many_requests_response_429;

pub async fn limit_http_request(ip: IpAddr, tx: Sender<Probe>) -> Option<http::Response<BoxBody<Bytes, hyper::Error>>> {
    let (probe, rx) = get_probe(ip);
    if let Err(err) = tx.send(probe).await {
        error!("couldn't send request probe to rate limiter: {err}");
        return Some(new_internal_error_response_500());
    }

    let resp = rx.await;
    if let Err(err) = resp {
        error!("error on receiving rate limiter result: {err}");
        return Some(new_internal_error_response_500());
    }

    let result = resp.expect("error on receiving rate limiter result");
    if let Err(_) = result {
        error!("rate limiter capacity reached for current timeframe");
        return Some(new_service_unavailable_error_503());
    }

    let can_resume = result.expect("rate limiter capacity reached for current timeframe");
    if !can_resume {
        return Some(new_too_many_requests_response_429());
    }
    None
}

pub fn get_rate_limit_handle(mut rx: mpsc::Receiver<Probe>, limiter_cfg: RateLimit) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut limiter = RateLimiter::new(
            limiter_cfg.max,
            Duration::from_secs(u64::from(limiter_cfg.window)),
            limiter_cfg.capacity,
        );
        while let Some(probe) = rx.recv().await {
            let result = limiter.can_resume(probe.ip);
            let _ = probe.resp.send(result);
        }
    })
}

fn get_probe(ip: IpAddr) -> (Probe, oneshot::Receiver<Response>) {
    let (tx, rx) = oneshot::channel();
    (Probe { ip, resp: tx }, rx)
}

type Response = Result<bool, ()>;
type Responder = oneshot::Sender<Response>;
pub struct Probe {
    ip: IpAddr,
    resp: Responder,
}

struct RateLimiterBucket {
    starts_at: Instant,
    inner: HashMap<IpAddr, Counter>,
}
struct RateLimiter {
    limit: u16,
    sampling_period: Duration,
    bucket_green: RateLimiterBucket,
    bucket_blue: RateLimiterBucket,
}

#[derive(Debug)]
struct Counter {
    pub sum: u16,
}

impl RateLimiterBucket {
    pub fn new(starts_at: Instant, capacity: usize) -> Self {
        Self {
            starts_at,
            inner: HashMap::with_capacity(capacity),
        }
    }
}

impl RateLimiter {
    pub fn new(limit: u16, sampling_period: Duration, capacity: usize) -> Self {
        let mut sanitized_limit = limit;
        if limit == u16::MAX {
            sanitized_limit = limit - 1;
        }

        let now = Instant::now();
        let before = create_prev_window(now, sampling_period);

        let bucket_green = RateLimiterBucket::new(now, capacity);
        let bucket_blue = RateLimiterBucket::new(before, capacity);

        Self {
            limit: sanitized_limit,
            sampling_period,
            bucket_green,
            bucket_blue,
        }
    }

    pub fn can_resume(&mut self, ip: IpAddr) -> Result<bool, ()> {
        if self.limit == 0 {
            return Ok(false);
        }

        let is_green_bucket_current = self.bucket_green.starts_at >= self.bucket_blue.starts_at;
        let starts_at = match is_green_bucket_current {
            true => self.bucket_green.starts_at,
            false => self.bucket_blue.starts_at,
        };
        let now = Instant::now();
        if !self.is_within_curr_bucket_window(now, starts_at) && self.sampling_period > Duration::from_nanos(0) {
            let capacity = self.bucket_green.inner.capacity();
            if self.is_outside_next_monothonic_window(now, self.bucket_green.starts_at) {
                self.bucket_green = RateLimiterBucket::new(now, capacity);
                self.bucket_blue = RateLimiterBucket::new(now, capacity);
            } else {
                // current bucket becomes previous
                if is_green_bucket_current {
                    let starts_at = self.bucket_green.starts_at + self.sampling_period;
                    self.bucket_blue = RateLimiterBucket::new(starts_at, capacity);
                } else {
                    let starts_at = self.bucket_blue.starts_at + self.sampling_period;
                    self.bucket_green = RateLimiterBucket::new(starts_at, capacity);
                }
            }
        }

        let is_green_bucket_current = self.bucket_green.starts_at >= self.bucket_blue.starts_at;
        let (curr_bucket, prev_bucket) = match is_green_bucket_current {
            true => (&mut self.bucket_green, &mut self.bucket_blue),
            false => (&mut self.bucket_blue, &mut self.bucket_green),
        };

        let curr_sum;
        if let Some(counter) = curr_bucket.inner.get_mut(&ip) {
            counter.increment();
            curr_sum = counter.sum;
        } else if curr_bucket.inner.capacity() == curr_bucket.inner.len() {
            return Err(());
        } else {
            let mut counter = Counter::new();
            counter.increment();
            curr_sum = counter.sum;
            curr_bucket.inner.insert(ip, counter);
        }

        let prev_sum = match prev_bucket.inner.get(&ip) {
            Some(c) => c.sum,
            None => 0,
        };

        let approx = get_approx(prev_sum, curr_bucket.starts_at.elapsed(), self.sampling_period);
        Ok(u64::from(self.limit) >= approx + u64::from(curr_sum))
    }

    fn is_within_curr_bucket_window(&self, now: Instant, curr_starts_at: Instant) -> bool {
        let next_monothonic_window = curr_starts_at + self.sampling_period;
        now < next_monothonic_window
    }

    fn is_outside_next_monothonic_window(&self, now: Instant, curr_starts_at: Instant) -> bool {
        let next_monothonic_window = curr_starts_at + 2 * self.sampling_period;
        now >= next_monothonic_window
    }
}

impl Counter {
    pub fn new() -> Self {
        Self { sum: 0 }
    }

    pub fn increment(&mut self) {
        self.sum = self.sum.saturating_add(1);
    }
}

fn get_approx(prev_counter: u16, window_needle: Duration, sampling_period: Duration) -> u64 {
    if window_needle >= sampling_period {
        return 0;
    }

    u64::from(prev_counter) * (sampling_period.as_secs() - window_needle.as_secs()) / sampling_period.as_secs()
}

fn create_prev_window(instant: Instant, sampling_period: Duration) -> Instant {
    if instant.elapsed() < sampling_period {
        return instant;
    }
    instant - sampling_period
}

#[cfg(feature = "test-utils")]
#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::time::sleep;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn test_rate_limiter_alg() {
        // Tests example form https://blog.cloudflare.com/counting-things-a-lot-of-different-things/
        //
        // "Let's say I set a limit of 50 requests per minute on an API endpoint.
        // In this situation, I did 18 requests during the current minute, which started 15 seconds ago
        // and 42 requests during the entire previous minute."
        //
        // rate = 42 * ((60-15)/60) + 18
        //      = 42 * 0.75 + 18
        //      = 49.5 requests
        let limit = 50;
        let sampling_period = Duration::from_secs(60);
        let mut r = RateLimiter::new(limit, sampling_period, 2);
        let ip = Ipv4Addr::new(1, 1, 1, 1).into();

        for _ in 0..42 {
            assert!(r.can_resume(ip).unwrap(), "should resume until limit is not reached");
        }

        sleep(sampling_period + Duration::from_secs(15)).await;
        for _ in 0..19 {
            assert!(r.can_resume(ip).unwrap(), "should resume for 42 * ((60-15)/60) + 19 = 50");
        }

        assert!(!r.can_resume(ip).unwrap(), "should break for 42 * ((60-15)/60) + 20 = 51");

        sleep(Duration::from_secs(3)).await;
        assert!(r.can_resume(ip).unwrap(), "should resume for 42 * ((60-(15+3))/60) + 21 = 50");

        sleep(2 * sampling_period).await;
        for _ in 0..limit {
            assert!(r.can_resume(ip).unwrap(), "should allow until limit is not reached");
        }
        for _ in 0..u16::MAX {
            assert!(!r.can_resume(ip).unwrap(), "should break when limit reached");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_rate_limiter_backpressure() {
        let sampling_period = Duration::new(1, 0);
        let ips = [
            Ipv4Addr::new(0, 0, 0, 0).into(),
            Ipv4Addr::new(1, 1, 1, 1).into(),
            Ipv4Addr::new(2, 2, 2, 2).into(),
            Ipv4Addr::new(3, 3, 3, 3).into(),
            Ipv4Addr::new(4, 4, 4, 4).into(),
            Ipv4Addr::new(5, 5, 5, 5).into(),
            Ipv4Addr::new(6, 6, 6, 6).into(),
            Ipv4Addr::new(7, 7, 7, 7).into(),
            Ipv4Addr::new(8, 8, 8, 8).into(),
        ];
        // quote from https://doc.rust-lang.org/std/collections/struct.HashMap.html#method.with_capacity
        // "This method is allowed to allocate for more elements than capacity. If capacity is zero, the hash map will not allocate."
        //
        // 8 is the first number for which it is not allocating for more elements.
        let capacity = 8;
        let mut r = RateLimiter::new(10, sampling_period, capacity);
        for i in 0..ips.len() {
            if i > capacity {
                assert!(r.can_resume(ips[i]).is_err(), "error - should backpressure on this IP");
            }
            assert!(r.can_resume(ips[i]).unwrap());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_rate_limiter_boundary_single_ip() {
        let ip = Ipv4Addr::new(1, 1, 1, 1).into();
        let mut r = RateLimiter::new(1, Duration::new(1, 0), 2);

        assert!(r.can_resume(ip).unwrap(), "should allow once when limit is 1");
        assert!(!r.can_resume(ip).unwrap(), "should block n 2nd attempt when limit is 1");

        let mut r = RateLimiter::new(0, Duration::new(1, 0), 2);
        assert!(!r.can_resume(ip).unwrap(), "should treat zero limit as always limited");
        assert!(!r.can_resume(ip).unwrap(), "should treat zero limit as always limited");

        let mut r = RateLimiter::new(0, Duration::new(0, 0), 2);
        assert!(
            !r.can_resume(ip).unwrap(),
            "should treat zero limit as always limited, even when zero window"
        );
        assert!(
            !r.can_resume(ip).unwrap(),
            "should treat zero limit as always limited, even when zero window"
        );

        let mut r = RateLimiter::new(1, Duration::new(0, 0), 2);
        assert!(
            r.can_resume(ip).unwrap(),
            "allow - limit should take precedense over zero window"
        );
        assert!(
            !r.can_resume(ip).unwrap(),
            "block - limit should take precedense over zero window"
        );

        let mut r = RateLimiter::new(u16::MAX, Duration::new(1, 0), 2);
        for _ in 1..u16::MAX {
            assert!(r.can_resume(ip).unwrap(), "allow - should handle limit overflow");
        }
        for _ in 0..u16::MAX {
            assert!(!r.can_resume(ip).unwrap(), "block - should handle limit overflow");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_approx() {
        let sampling_period = Duration::from_secs(60);
        let mut counter: u16 = 0;
        sleep(sampling_period).await;
        for _ in 0..42 {
            counter = counter.saturating_add(1);
        }

        let start = Instant::now();
        assert_eq!(42, counter);
        assert_eq!(42, get_approx(counter, start.elapsed(), sampling_period));
        sleep(Duration::from_secs(15)).await;
        assert_eq!(31, get_approx(counter, start.elapsed(), sampling_period));
    }

    #[tokio::test(start_paused = true)]
    async fn test_create_prev_window() {
        let sampling_window = Duration::from_secs(60);

        for tc in vec![0, 13, 59] {
            let now = Instant::now();
            let offset = Duration::from_secs(tc);
            sleep(offset).await;
            assert_eq!(now, create_prev_window(now, sampling_window));
        }

        for tc in vec![60, 73, 119] {
            let now = Instant::now();
            let offset = Duration::from_secs(tc);
            sleep(offset).await;
            assert_eq!(now - sampling_window, create_prev_window(now, sampling_window));
        }
    }
}
