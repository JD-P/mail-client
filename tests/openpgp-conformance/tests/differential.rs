use openpgp_conformance::{DifferentialInput, DifferentialOperation, Harness};

#[test]
#[ignore = "requires Linux, cc, and exactly GnuPG 2.4.7"]
fn deterministic_gnupg_rpgp_matrix() {
    let harness = Harness::new().expect("initialize differential harness");
    let payloads: &[&[u8]] = &[
        b"",
        b"OpenPGP differential test\n",
        b"binary:\0\xff\x80\n",
        &[0x5a; 4096],
    ];
    let starts = [0, 1, 127, 254];
    let operations = [
        DifferentialOperation::RsaSignature,
        DifferentialOperation::RsaSessionKey,
        DifferentialOperation::Aes256Seipdv1,
    ];

    for operation in operations {
        for &random_start in &starts {
            for &payload in payloads {
                harness
                    .compare(DifferentialInput {
                        operation,
                        random_start,
                        payload,
                    })
                    .unwrap_or_else(|error| {
                        panic!(
                            "{operation:?}, random_start={random_start}, payload_len={}: {error:#}",
                            payload.len()
                        )
                    });
            }
        }
    }
}
