use std::{io::Write, time::SystemTime};

use pgp::{
    composed::key::SecretKey,
    packet::{write_packet, KeyFlags, UserId},
    ser::Serialize,
    types::{PlainSecretParams, PublicKeyTrait, PublicParams, SecretKeyTrait},
    KeyDetails, KeyType,
};

use num_bigint::traits::ModInverse as _;
use num_bigint::BigUint;
use rand::{CryptoRng, Rng};
use rsa::{traits::PrivateKeyParts as _, traits::PublicKeyParts as _, RsaPrivateKey};
use std::default::Default as D;
use testresult::TestResult as Result;

pub fn generate_key<R: Rng + CryptoRng>(
    mut rng: R,
    bit_size: usize,
) -> Result<(PublicParams, PlainSecretParams, RsaPrivateKey)> {
    let key = RsaPrivateKey::new_with_exp(&mut rng, bit_size, &257u16.into())?;

    let p = &key.primes()[0];
    let q = &key.primes()[1];
    let u = p
        .clone()
        .mod_inverse(q)
        .expect("invalid prime")
        .to_biguint()
        .expect("invalid prime");

    Ok((
        PublicParams::RSA {
            n: key.n().into(),
            e: key.e().into(),
        },
        PlainSecretParams::RSA {
            d: key.d().into(),
            p: p.into(),
            q: q.into(),
            u: u.into(),
        },
        key,
    ))
}

fn main() -> Result<()> {
    let (public_params, plain, key) = generate_key(rand::thread_rng(), 2048)?;
    let secret_params = pgp::types::SecretParams::Plain(plain);

    let mut keyflags = KeyFlags::default();
    keyflags.set_certify(true);
    keyflags.set_sign(true);

    let public = pgp::packet::PublicKey::new(
        D::default(),
        D::default(),
        KeyType::Rsa(2048).to_alg(),
        SystemTime::now().into(),
        None,
        public_params,
    )?;
    let details = KeyDetails::new(
        UserId::from_str(pgp::types::Version::New, "test"),
        vec![],
        vec![],
        keyflags,
        D::default(),
        D::default(),
        D::default(),
        D::default(),
        None,
    );

    let secret = pgp::packet::SecretKey::new(public, secret_params);
    let details = details.sign(rand::thread_rng(), &secret, String::new)?;

    let mut writer = std::io::stdout(); //vec![];
    write_packet(&mut writer, &secret)?;
    details.to_writer(&mut writer)?;
    Ok(())
}
