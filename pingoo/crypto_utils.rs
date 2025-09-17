use aws_lc_rs::constant_time::verify_slices_are_equal;

pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    return verify_slices_are_equal(a, b).is_ok();
}
