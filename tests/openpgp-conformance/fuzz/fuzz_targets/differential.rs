#![no_main]

use std::sync::{Mutex, OnceLock};

use libfuzzer_sys::fuzz_target;
use openpgp_conformance::{DifferentialInput, Harness};

static HARNESS: OnceLock<Mutex<Harness>> = OnceLock::new();

fuzz_target!(|input: &[u8]| {
    let Some(case) = DifferentialInput::from_fuzz_bytes(input) else {
        return;
    };
    let harness =
        HARNESS.get_or_init(|| {
            Mutex::new(Harness::new().unwrap_or_else(|error| {
                panic!("initialize OpenPGP differential harness: {error:#}")
            }))
        });
    harness
        .lock()
        .expect("differential harness mutex poisoned")
        .compare(case)
        .unwrap_or_else(|error| panic!("OpenPGP differential mismatch: {error:#}"));
});
