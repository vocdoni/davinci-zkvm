#![no_main]
ziskos::entrypoint!(main);

mod bn254;
mod ecdsa;
mod groth16;
mod hash;
mod io;
mod types;

use ziskos::{read_input_slice, set_output};

fn main() {
    let input = read_input_slice();
    let mut fail_mask: u32 = 0;

    let parsed               = io::parse_input(input, &mut fail_mask);
    let batch_ok             = groth16::verify_batch(&parsed, &mut fail_mask);
    let (has_ecdsa, ecdsa_ok) = ecdsa::verify_batch(&parsed, &mut fail_mask);

    let overall_ok = fail_mask == 0 && batch_ok && (!has_ecdsa || ecdsa_ok);
    set_output(0, overall_ok as u32);
    set_output(1, fail_mask);
    set_output(2, parsed.log_n as u32);
    set_output(3, parsed.nproofs as u32);
    set_output(4, parsed.n_public as u32);
    set_output(5, input.len() as u32);
    set_output(6, parsed.bytes_consumed as u32);
    set_output(7, batch_ok as u32);
    set_output(8, match (has_ecdsa, ecdsa_ok) {
        (true,  true)  => 1,
        (true,  false) => 0,
        (false, _)     => 2, // ECDSA block not present
    });
}
