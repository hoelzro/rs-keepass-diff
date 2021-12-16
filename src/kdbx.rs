use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::convert::{TryFrom, TryInto};

use crypto::aes;
use crypto::buffer::{BufferResult, RefReadBuffer, RefWriteBuffer, ReadBuffer, WriteBuffer};
use crypto::blockmodes;
use crypto::digest::Digest;
use crypto::salsa20::Salsa20;
use crypto::sha2::Sha256;
use crypto::symmetriccipher::SynchronousStreamCipher;

use flate2::read::GzDecoder;

use serde::Deserialize;
use std::io::Read;

const MAGIC_SIGNATURE_1: u32 = 0x9AA2D903;
const MAGIC_SIGNATURE_2: u32 = 0xB54BFB67;
const FILE_VERSION_CRITICAL_MASK: u32 = 0xFFFF0000;
const FILE_VERSION_3: u32 = 0x00030000;
// XXX can I infer the length?
const CIPHER_AES256: [u8; 16] = [0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff];
const COMPRESSION_ALGORITHM_GZIP: u32 = 1;
#[allow(dead_code)]
const STREAM_ALGORITHM_ARC_FOUR_VARIANT: u32 = 1;
const STREAM_ALGORITHM_SALSA20: u32 = 2;
#[allow(dead_code)]
const STREAM_ALGORITHM_CHACHA20: u32 = 3;

const KEEPASS_IV: [u8; 8] = [0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a];

#[derive(Debug)]
pub enum KeepassLoadError {
    IO(io::Error),
    CipherError(crypto::symmetriccipher::SymmetricCipherError),
    XMLError(quick_xml::DeError),
    Base64Error(base64::DecodeError),
    UTF8Error(std::string::FromUtf8Error),
    BadMagicSignature,
    BadFileVersion,
    InvalidFieldID,
    InvalidFieldLength,
    UnsupportedCipher,
    UnsupportedCompressionAlgorithm,
    UnsupportedStreamAlgorithm,
    StreamStartMismatch,
    InvalidFinalHash,
    Unimplemented,
}

impl Display for KeepassLoadError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "failed to load KeePass database: {:?}", self)
    }
}

impl Error for KeepassLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            KeepassLoadError::IO(err)          => Some(err),
            //KeepassLoadError::CipherError(err) => Some(err),
            KeepassLoadError::XMLError(err)    => Some(err),
            KeepassLoadError::Base64Error(err) => Some(err),
            KeepassLoadError::UTF8Error(err)   => Some(err),

            _ => None,
        }
    }
}

impl From<io::Error> for KeepassLoadError {
    fn from(err: io::Error) -> KeepassLoadError {
        KeepassLoadError::IO(err)
    }
}

impl From<crypto::symmetriccipher::SymmetricCipherError> for KeepassLoadError {
    fn from(err: crypto::symmetriccipher::SymmetricCipherError) -> KeepassLoadError {
        KeepassLoadError::CipherError(err)
    }
}

impl From<quick_xml::DeError> for KeepassLoadError {
    fn from(err: quick_xml::DeError) -> KeepassLoadError {
        KeepassLoadError::XMLError(err)
    }
}

impl From<base64::DecodeError> for KeepassLoadError {
    fn from(err: base64::DecodeError) -> KeepassLoadError {
        KeepassLoadError::Base64Error(err)
    }
}

impl From<std::string::FromUtf8Error> for KeepassLoadError {
    fn from(err: std::string::FromUtf8Error) -> KeepassLoadError {
        KeepassLoadError::UTF8Error(err)
    }
}

enum FieldID {
    EndOfHeader,
    Comment,
    CipherID,
    CompressionFlags,
    MasterSeed,
    TransformSeed,
    TransformRounds,
    EncryptionIV,
    ProtectedStreamKey,
    StreamStartBytes,
    InnerRandomStreamID,
    KdfParameters,
    PublicCustomData,
}

impl TryFrom<u8> for FieldID {
    type Error = KeepassLoadError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0  => Ok(FieldID::EndOfHeader),
            1  => Ok(FieldID::Comment),
            2  => Ok(FieldID::CipherID),
            3  => Ok(FieldID::CompressionFlags),
            4  => Ok(FieldID::MasterSeed),
            5  => Ok(FieldID::TransformSeed),
            6  => Ok(FieldID::TransformRounds),
            7  => Ok(FieldID::EncryptionIV),
            8  => Ok(FieldID::ProtectedStreamKey),
            9  => Ok(FieldID::StreamStartBytes),
            10 => Ok(FieldID::InnerRandomStreamID),
            11 => Ok(FieldID::KdfParameters),
            12 => Ok(FieldID::PublicCustomData),

            _ => Err(KeepassLoadError::InvalidFieldID),
        }
    }
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct KeeValuePair {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Deserialize, Debug, Default)]
#[serde(rename_all = "PascalCase")]
pub struct KeepassDatabaseEntryHistory {
    #[serde(rename = "Entry", default)]
    pub entries: Vec<KeepassDatabaseEntry>,
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct KeepassDatabaseEntry {
    #[serde(rename = "String")]
    pub key_values: Vec<KeeValuePair>,

    #[serde(default)]
    pub history: KeepassDatabaseEntryHistory,
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct KeepassDatabaseGroup {
    #[serde(default)]
    pub name: String,

    #[serde(rename = "Group", default)]
    pub groups: Vec<KeepassDatabaseGroup>,

    #[serde(rename = "Entry", default)]
    pub entries: Vec<KeepassDatabaseEntry>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct KeepassDatabase {
    pub root: KeepassDatabaseGroup
}

fn validate_signature(mut db_file: impl Read) -> Result<(), KeepassLoadError> {
    let mut buf = [0u8; 4];

    db_file.read_exact(&mut buf)?;

    let magic1 = u32::from_le_bytes(buf);

    if magic1 != MAGIC_SIGNATURE_1 {
        return Err(KeepassLoadError::BadMagicSignature);
    }

    db_file.read_exact(&mut buf)?;

    let magic2 = u32::from_le_bytes(buf);

    if magic2 != MAGIC_SIGNATURE_2 {
        return Err(KeepassLoadError::BadMagicSignature);
    }

    db_file.read_exact(&mut buf)?;

    let version = u32::from_le_bytes(buf) & FILE_VERSION_CRITICAL_MASK;

    if version != FILE_VERSION_3 {
        return Err(KeepassLoadError::BadFileVersion);
    }

    Ok(())
}

struct KeepassHeader {
    master_seed: [u8; 32],
    transform_seed: [u8; 32],
    encryption_iv: [u8; 16],
    protected_stream_key: [u8; 32],
    stream_start_bytes: [u8; 32],
    transform_rounds: u64,
}

fn read_database_headers(mut db_file: impl Read) -> Result<KeepassHeader, KeepassLoadError> {
    let mut master_seed = [0u8; 32];
    let mut transform_seed = [0u8; 32];
    let mut encryption_iv = [0u8; 16];
    let mut transform_rounds = 0u64;
    let mut protected_stream_key = [0u8; 32];
    let mut stream_start_bytes = [0u8; 32];

    loop {
        let mut field_id_buf = [0u8; 1];
        let mut field_length_buf = [0u8; 2];

        db_file.read_exact(&mut field_id_buf)?;
        db_file.read_exact(&mut field_length_buf)?;

        let field_id: FieldID = field_id_buf[0].try_into()?;
        let field_length = u16::from_le_bytes(field_length_buf);

        let mut field_data = vec![0; field_length.into()];

        db_file.read_exact(field_data.as_mut_slice())?;

        match field_id {
            FieldID::EndOfHeader => {
                break;
            },
            FieldID::CipherID => {
                if field_data.as_slice() != CIPHER_AES256 {
                    return Err(KeepassLoadError::UnsupportedCipher);
                }
            },
            FieldID::CompressionFlags => {
                let compression_algorithm = u32::from_le_bytes(field_data.try_into().map_err(|_| KeepassLoadError::InvalidFieldLength)?);
                if compression_algorithm != COMPRESSION_ALGORITHM_GZIP {
                    return Err(KeepassLoadError::UnsupportedCompressionAlgorithm);
                }
            },
            FieldID::MasterSeed => {
                master_seed = field_data.try_into().map_err(|_| KeepassLoadError::InvalidFieldLength)?;
            },
            FieldID::TransformSeed => {
                transform_seed = field_data.try_into().map_err(|_| KeepassLoadError::InvalidFieldLength)?;
            },
            FieldID::TransformRounds => {
                transform_rounds = u64::from_le_bytes(field_data.try_into().map_err(|_| KeepassLoadError::InvalidFieldLength)?);
            },
            FieldID::EncryptionIV => {
                encryption_iv = field_data.try_into().map_err(|_| KeepassLoadError::InvalidFieldLength)?;
            },
            FieldID::ProtectedStreamKey => {
                protected_stream_key = field_data.try_into().map_err(|_| KeepassLoadError::InvalidFieldLength)?;
            },
            FieldID::StreamStartBytes => {
                stream_start_bytes = field_data.try_into().map_err(|_| KeepassLoadError::InvalidFieldLength)?;
            },
            FieldID::InnerRandomStreamID => {
                let stream_id = u32::from_le_bytes(field_data.try_into().map_err(|_| KeepassLoadError::InvalidFieldLength)?);
                if stream_id != STREAM_ALGORITHM_SALSA20 {
                    return Err(KeepassLoadError::UnsupportedStreamAlgorithm);
                }
            },

            FieldID::Comment => {
                return Err(KeepassLoadError::Unimplemented);
            },
            FieldID::KdfParameters => {
                return Err(KeepassLoadError::Unimplemented);
            },
            FieldID::PublicCustomData => {
                return Err(KeepassLoadError::Unimplemented);
            },
        }
    }

    // XXX verify we got all the fields

    Ok(KeepassHeader{
        transform_rounds,
        master_seed,
        protected_stream_key,
        transform_seed,
        encryption_iv,
        stream_start_bytes,
    })
}

fn compute_master_key(header: &KeepassHeader, password: String) -> Result<[u8; 32], KeepassLoadError> {
    let password_hash = {
        let mut hasher = Sha256::new();
        hasher.input_str(&password);
        let mut hash: [u8; 32] = [0; 32];
        hasher.result(&mut hash);
        hash
    };

    let composite_key = {
        let mut hasher = Sha256::new();
        hasher.input(&password_hash);
        let mut hash: [u8; 32] = [0; 32];
        hasher.result(&mut hash);
        hash
    };

    let mut transformed_key = composite_key;

    for _ in 0..header.transform_rounds {
        // XXX do I really need to recreate this over and over?
        let mut aes = aes::ecb_encryptor(aes::KeySize::KeySize256, &header.transform_seed, blockmodes::NoPadding);
        let mut this_rounds_output = [0u8; 32];
        aes.encrypt(&mut RefReadBuffer::new(&transformed_key), &mut RefWriteBuffer::new(&mut this_rounds_output), true)?;
        transformed_key.copy_from_slice(&this_rounds_output);
    }

    transformed_key = {
        let mut hasher = Sha256::new();
        hasher.input(&transformed_key);
        let mut hash: [u8; 32] = [0; 32];
        hasher.result(&mut hash);
        hash
    };

    let master_key = {
        let mut hasher = Sha256::new();
        hasher.input(&header.master_seed);
        hasher.input(&transformed_key);
        let mut hash: [u8; 32] = [0; 32];
        hasher.result(&mut hash);
        hash
    };

    Ok(master_key)
}

fn read_database_blocks(header: &KeepassHeader, mut plaintext: impl Read) -> Result<KeepassDatabase, KeepassLoadError> {
    loop {
        let mut buf = [0u8; 4];
        plaintext.read_exact(&mut buf)?;
        let _block_id = u32::from_le_bytes(buf);

        let mut block_hash = [0u8; 32];
        plaintext.read_exact(&mut block_hash)?;

        plaintext.read_exact(&mut buf)?;
        let block_size = u32::from_le_bytes(buf);

        if block_size == 0 {
            if block_hash != [0u8; 32] {
                return Err(KeepassLoadError::InvalidFinalHash);
            }

            panic!("premature EOF");
        }

        // XXX I like the idea of a block returning an immutable variable for this...
        let mut block_data = vec![0; block_size as usize];

        plaintext.read_exact(&mut block_data)?;

        let mut gunzip = GzDecoder::new(block_data.as_slice());
        let mut uncompressed = String::new();
        gunzip.read_to_string(&mut uncompressed)?;

        let mut db: KeepassDatabase = quick_xml::de::from_str(&uncompressed)?;

        let password_decryption_key = {
            let mut hasher = Sha256::new();
            hasher.input(&header.protected_stream_key);
            let mut hash: [u8; 32] = [0; 32];
            hasher.result(&mut hash);
            hash
        };

        let mut password_decryptor = Salsa20::new(&password_decryption_key, &KEEPASS_IV);
        return Ok(KeepassDatabase{root: decrypt_passwords(&mut db.root, &mut password_decryptor)?});
    }
}

pub fn load_database(mut db_file: impl Read, password: String) -> Result<KeepassDatabase, KeepassLoadError> {
    validate_signature(&mut db_file)?;

    let header = read_database_headers(&mut db_file)?;

    let master_key = compute_master_key(&header, password)?;

    let mut aes = aes::cbc_decryptor(aes::KeySize::KeySize256, &master_key, &header.encryption_iv, blockmodes::NoPadding);

    let mut cipher_text = Vec::new();
    db_file.read_to_end(&mut cipher_text)?;

    let mut plain_text = Vec::new();
    let mut cipher_text_buffer = RefReadBuffer::new(&cipher_text);
    let mut work_space = [0; 4096];
    let mut plain_text_buffer = RefWriteBuffer::new(&mut work_space);

    loop {
        let res = aes.decrypt(&mut cipher_text_buffer, &mut plain_text_buffer, true)?;
        plain_text.extend(plain_text_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match res {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => continue,
        }
    }

    let first_block_plaintext = &plain_text[..header.stream_start_bytes.len()];
    let mut remaining_plaintext = &plain_text[header.stream_start_bytes.len()..];

    if first_block_plaintext != header.stream_start_bytes {
        return Err(KeepassLoadError::StreamStartMismatch);
    }

    read_database_blocks(&header, &mut remaining_plaintext)
}

fn decrypt_entries(entries: &Vec<KeepassDatabaseEntry>, password_decryptor: &mut Salsa20) -> Result<Vec<KeepassDatabaseEntry>, KeepassLoadError> {
    let mut new_entries = Vec::with_capacity(entries.len());
    for entry in entries {
        let mut decrypted_key_values = Vec::with_capacity(entry.key_values.len());
        let mut decrypted_history = KeepassDatabaseEntryHistory{
            entries: vec![],
        };

        for kv in &entry.key_values {
            let value = if kv.key == "Password" { // XXX properly detecting the Protected attribute would be the right move here
                let ciphertext = base64::decode(kv.value.as_bytes())?;
                let mut password_buf = vec![0; ciphertext.len()];

                password_decryptor.process(ciphertext.as_slice(), password_buf.as_mut_slice());
                String::from_utf8(password_buf)?
            } else {
                kv.value.clone()
            };

            decrypted_key_values.push(KeeValuePair{
                key: kv.key.clone(),
                value: value,
            });
        }

        // process history just to thread the salsa20 state through
        for history_entry in &entry.history.entries {
            let mut decrypted_key_values = Vec::with_capacity(history_entry.key_values.len());

            for kv in &history_entry.key_values {
                let value = if kv.key == "Password" { // XXX properly detecting the Protected attribute would be the right move here
                    let ciphertext = base64::decode(kv.value.as_bytes())?;
                    let mut password_buf = vec![0; ciphertext.len()];

                    password_decryptor.process(ciphertext.as_slice(), password_buf.as_mut_slice());
                    String::from_utf8(password_buf)?
                } else {
                    kv.value.clone()
                };

                decrypted_key_values.push(KeeValuePair{
                    key: kv.key.clone(),
                    value: value,
                });
            }
            decrypted_history.entries.push(KeepassDatabaseEntry{
                key_values: decrypted_key_values,
                history: KeepassDatabaseEntryHistory{entries: vec![]},
            })
        }

        new_entries.push(KeepassDatabaseEntry{
            key_values: decrypted_key_values,
            history: decrypted_history,
        });
    }

    Ok(new_entries)
}

fn decrypt_passwords(group: &KeepassDatabaseGroup, password_decryptor: &mut Salsa20) -> Result<KeepassDatabaseGroup, KeepassLoadError> {
    let mut new_groups = Vec::with_capacity(group.groups.len());
    for subgroup in &group.groups {
        new_groups.push(decrypt_passwords(subgroup, password_decryptor)?);
    }

    let new_entries = decrypt_entries(&group.entries, password_decryptor)?;

    Ok(KeepassDatabaseGroup{
        name: group.name.clone(), // XXX is this right? do I want to copy the name, or copy a reference to a string?
        groups: new_groups,
        entries: new_entries,
    })
}
