// We need this macro because tracing expects the level to be const:
// https://github.com/tokio-rs/tracing/issues/2730
#[macro_export]
macro_rules! dynamic_event {
    ($level:expr, $($args:tt)*) => {{
        match $level {
            ::tracing::Level::TRACE => ::tracing::trace!($($args)*),
            ::tracing::Level::DEBUG => ::tracing::debug!($($args)*),
            ::tracing::Level::INFO => ::tracing::info!($($args)*),
            ::tracing::Level::WARN => ::tracing::warn!($($args)*),
            ::tracing::Level::ERROR => ::tracing::error!($($args)*),
        }
    }};
}
