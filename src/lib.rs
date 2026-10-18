//! Independent offline recovery. No dependency on Outis services or wallet packages.
use bip39::{Language, Mnemonic};
use crypto_bigint::{Encoding, NonZero, U256};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};
use starknet_crypto::{get_public_key, Felt, PedersenHasher};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// Permanent recovery parameters: changing these changes existing keys or addresses.
const ACCOUNT_CLASS: &str = "0x00eb49f5299d144f0b2e434e483758fb6d7d8241632534d86b098047fe4e2b42";
const AGENT_CLASS: &str = "0x01b69b7a78c6868b27d649f47e539b86fd26899292a8ebe01bae0613c5fe4e3f";
const ORDER: U256 =
    U256::from_be_hex("0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f");
// 2^256 - (2^256 mod ORDER), used for unbiased reduction.
const LIMIT: U256 =
    U256::from_be_hex("f80000000000020efffffffffffffff738a13b4b920e9411ae6da5f40b0358b1");
const ADDRESS_BOUND: U256 =
    U256::from_be_hex("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00");
const PHRASE_ERROR: &str = "Enter a valid 12-word Outis recovery phrase with its correct checksum";
pub type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Copy, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountKind {
    #[default]
    Account,
    Agent,
}

pub struct Options {
    pub network: String,
    pub index: u16,
    pub kind: AccountKind,
    pub pool: Option<U256>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            network: "SN_MAIN".into(),
            index: 0,
            kind: AccountKind::Account,
            pool: None,
        }
    }
}

impl Options {
    pub fn validate(&self) -> Result<()> {
        if self.network.is_empty()
            || self.network.len() > 31
            || !self
                .network
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err("Network must be an ASCII chain name, such as SN_MAIN or SN_SEPOLIA");
        }
        if self.index >= 1000 {
            return Err("Account index must be an integer from 0 through 999");
        }
        if self
            .pool
            .is_some_and(|p| p == U256::ZERO || p >= ADDRESS_BOUND)
        {
            return Err("Pool must be a valid, nonzero Starknet address");
        }
        Ok(())
    }
}

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct KeyPair {
    pub private_key: String,
    pub public_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Deployment {
    pub class_hash: &'static str,
    pub salt: &'static str,
    pub deployer: &'static str,
    pub constructor_calldata: Vec<String>,
}

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct Viewing {
    pub pool: String,
    pub private_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recovery {
    pub version: u8,
    pub network: String,
    pub chain_id: String,
    pub kind: AccountKind,
    pub index: u16,
    pub owner: KeyPair,
    pub address: String,
    pub deployment: Deployment,
    pub vault: KeyPair,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewing: Option<Viewing>,
}

// Rust's is_whitespace differs from JavaScript /\s/: notably U+0085 and U+FEFF.
fn js_whitespace(c: char) -> bool {
    matches!(c, '\u{0009}'..='\u{000d}' | '\u{0020}' | '\u{00a0}' | '\u{1680}'
        | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}'
        | '\u{205f}' | '\u{3000}' | '\u{feff}')
}

pub fn decode_phrase(phrase: &str) -> Result<Zeroizing<[u8; 16]>> {
    let lowercase = Zeroizing::new(phrase.to_lowercase());
    let spaced = Zeroizing::new(
        lowercase
            .split(js_whitespace)
            .filter(|w| !w.is_empty())
            .collect::<Vec<_>>()
            .join(" "),
    );
    let normalized = Zeroizing::new(spaced.nfkd().collect::<String>());
    // Enforce scure's ASCII-space word boundaries before the Rust mnemonic decoder.
    if normalized.split(' ').count() != 12
        || normalized
            .split(' ')
            .any(|w| w.is_empty() || !w.bytes().all(|b| b.is_ascii_lowercase()))
    {
        return Err(PHRASE_ERROR);
    }
    let mnemonic =
        Mnemonic::parse_in_normalized(Language::English, &normalized).map_err(|_| PHRASE_ERROR)?;
    let (entropy, length) = mnemonic.to_entropy_array();
    let entropy = Zeroizing::new(entropy);
    if length != 16 {
        return Err(PHRASE_ERROR);
    }
    let mut seed = Zeroizing::new([0; 16]);
    seed.copy_from_slice(&entropy[..16]);
    Ok(seed)
}

fn kdf(input: &[u8], label: &str) -> Zeroizing<[u8; 32]> {
    let mut output = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(&[0; 32]), input)
        .expand(label.as_bytes(), output.as_mut())
        .expect("32-byte HKDF output");
    output
}

pub fn root_from_phrase(phrase: &str) -> Result<Zeroizing<[u8; 32]>> {
    Ok(kdf(decode_phrase(phrase)?.as_ref(), "outis/seed/v1"))
}

fn reduce(value: &U256, modulus: U256) -> U256 {
    value.rem(&NonZero::new(modulus).unwrap())
}

fn hex(value: &U256) -> String {
    format!("0x{value:064x}")
}
fn felt_hex(value: &Felt) -> String {
    hex(&U256::from_be_bytes(value.to_bytes_be()))
}

pub fn parse_pool(value: &str) -> Result<U256> {
    let digits = value.strip_prefix("0x").ok_or("Pool must begin with 0x")?;
    if digits.is_empty() || digits.len() > 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Pool must be a hexadecimal address beginning with 0x");
    }
    let pool = U256::from_be_hex(&format!("{digits:0>64}"));
    if pool == U256::ZERO || pool >= ADDRESS_BOUND {
        return Err("Pool must be a valid, nonzero Starknet address");
    }
    Ok(pool)
}

fn grind(material: &[u8; 32]) -> Result<Zeroizing<U256>> {
    for counter in 0u32..=100_000 {
        let bytes = counter.to_be_bytes();
        let start = bytes.iter().position(|b| *b != 0).unwrap_or(3);
        let mut hash = Sha256::new();
        hash.update(material);
        hash.update(&bytes[start..]);
        let candidate = Zeroizing::new(U256::from_be_slice(&hash.finalize()));
        if *candidate < LIMIT {
            let key = Zeroizing::new(reduce(&candidate, ORDER));
            if *key == U256::ZERO {
                return Err("Derived an invalid zero private key");
            }
            return Ok(key);
        }
    }
    Err("No Stark key found")
}

fn key(root: &[u8; 32], label: &str) -> Result<KeyPair> {
    let private = grind(&kdf(root, label))?;
    let bytes = Zeroizing::new(private.to_be_bytes());
    let public = get_public_key(&Felt::from_bytes_be(&bytes));
    Ok(KeyPair {
        private_key: hex(&private),
        public_key: felt_hex(&public),
    })
}

fn hash_elements(elements: &[Felt]) -> Felt {
    let mut hasher = PedersenHasher::new();
    for element in elements {
        hasher.update(*element);
    }
    hasher.finalize()
}

fn viewing_key(private: &str, chain: Felt, account: Felt, pool: U256) -> Result<String> {
    let private = Zeroizing::new(U256::from_be_hex(&private[2..]).to_be_bytes());
    for counter in 0u32..=u32::MAX {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(private.as_ref()).expect("HMAC accepts 32 bytes");
        mac.update(b"STRK20_ACCOUNT_LEAF_V1");
        mac.update(&1u32.to_be_bytes());
        mac.update(&chain.to_bytes_be());
        mac.update(&account.to_bytes_be());
        mac.update(&pool.to_be_bytes());
        mac.update(&[0; 16]);
        mac.update(&counter.to_be_bytes());
        let candidate = Zeroizing::new(U256::from_be_slice(&mac.finalize().into_bytes()));
        if *candidate >= LIMIT {
            continue;
        }
        let scalar = Zeroizing::new(reduce(&candidate, ORDER));
        let folded = Zeroizing::new((*scalar).min(ORDER.wrapping_sub(&scalar)));
        if *folded >= U256::ONE && *folded < ORDER.shr_vartime(1) {
            return Ok(hex(&folded));
        }
    }
    Err("No viewing key found")
}

pub fn recover(phrase: &str, options: &Options) -> Result<Recovery> {
    options.validate()?;
    let root = root_from_phrase(phrase)?;
    let (role, class_hash) = match options.kind {
        AccountKind::Account => ("owner", ACCOUNT_CLASS),
        AccountKind::Agent => ("agent", AGENT_CLASS),
    };
    let owner = key(
        &root,
        &format!("outis/{role}/v1/{}/{}", options.network, options.index),
    )?;
    let public = Felt::from_hex(&owner.public_key).expect("derived public key");
    let mut calldata = vec![Felt::ZERO, public];
    let mut constructor_calldata = vec!["0x0".into(), owner.public_key.clone()];
    if matches!(options.kind, AccountKind::Account) {
        calldata.push(Felt::ONE);
        constructor_calldata.push("0x1".into());
    }
    let hashed = hash_elements(&[
        Felt::from_bytes_be_slice(b"STARKNET_CONTRACT_ADDRESS"),
        Felt::ZERO,
        Felt::ZERO,
        Felt::from_hex(class_hash).expect("class hash"),
        hash_elements(&calldata),
    ]);
    let address = reduce(&U256::from_be_bytes(hashed.to_bytes_be()), ADDRESS_BOUND);
    let chain = Felt::from_bytes_be_slice(options.network.as_bytes());
    let viewing = options
        .pool
        .map(|pool| {
            Ok(Viewing {
                pool: hex(&pool),
                private_key: viewing_key(
                    &owner.private_key,
                    chain,
                    Felt::from_bytes_be(&address.to_be_bytes()),
                    pool,
                )?,
            })
        })
        .transpose()?;
    Ok(Recovery {
        version: 1,
        network: options.network.clone(),
        chain_id: format!("{chain:#x}"),
        kind: options.kind,
        index: options.index,
        owner,
        address: hex(&address),
        deployment: Deployment {
            class_hash,
            salt: "0x0",
            deployer: "0x0",
            constructor_calldata,
        },
        vault: key(&root, "outis/vault/wallet/v1")?,
        viewing,
    })
}
