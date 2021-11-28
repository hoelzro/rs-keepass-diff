use std::convert::{TryFrom, TryInto};
use std::env;
use std::io;
use std::io::Read;
use std::fs::File;
use std::process;

use crypto::aes;
use crypto::buffer::{BufferResult, RefReadBuffer, RefWriteBuffer, ReadBuffer, WriteBuffer};
use crypto::blockmodes;
use crypto::digest::Digest;
use crypto::sha2::Sha256;

use flate2::read::GzDecoder;

use serde::Deserialize;

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

// XXX break this out into its own file/module/library/package/crate/whatever
fn read_password() -> String {
    "abc123".to_string()
}

#[derive(Debug)]
enum KeepassLoadError {
    IO(io::Error),
    BadMagicSignature,
    BadFileVersion,
    UnsupportedCipher,
    UnsupportedCompressionAlgorithm,
    UnsupportedStreamAlgorithm,
    StreamStartMismatch,
    InvalidFinalHash,
    Unimplemented,
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
    type Error = ();

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

            _ => Err(()),
        }
    }
}

#[derive(Clone, Deserialize, Debug)]
struct KeeValuePair {
    Key: String,
    Value: String,
}

#[derive(Clone, Deserialize, Debug)]
struct KeepassDatabaseEntry {
    #[serde(rename = "String")]
    KeyValues: Vec<KeeValuePair>,
}

#[derive(Clone, Deserialize, Debug)]
struct KeepassDatabaseGroup {
    #[serde(default)]
    Name: String,

    #[serde(rename = "Group", default)]
    Groups: Vec<KeepassDatabaseGroup>,

    #[serde(rename = "Entry", default)]
    Entries: Vec<KeepassDatabaseEntry>,
}

#[derive(Deserialize, Debug)]
struct KeepassDatabase {
    Root: KeepassDatabaseGroup
}

// XXX make it a Read or something
fn load_database(mut db_file: File, password: String) -> Result<KeepassDatabase, KeepassLoadError> {
    let mut buf = [0u8; 4];

    // XXX there has to be a way to improve this
    if let Err(err) = db_file.read_exact(&mut buf) {
        return Err(KeepassLoadError::IO(err))
    }

    let magic1 = u32::from_le_bytes(buf);

    if magic1 != MAGIC_SIGNATURE_1 {
        return Err(KeepassLoadError::BadMagicSignature);
    }

    if let Err(err) = db_file.read_exact(&mut buf) {
        return Err(KeepassLoadError::IO(err))
    }

    let magic2 = u32::from_le_bytes(buf);

    if magic2 != MAGIC_SIGNATURE_2 {
        return Err(KeepassLoadError::BadMagicSignature);
    }

    if let Err(err) = db_file.read_exact(&mut buf) {
        return Err(KeepassLoadError::IO(err))
    }

    let version = u32::from_le_bytes(buf) & FILE_VERSION_CRITICAL_MASK;

    if version != FILE_VERSION_3 {
        return Err(KeepassLoadError::BadFileVersion);
    }

    // XXX is using with_capacity actually helpful here?
    let mut master_seed = Vec::with_capacity(32);
    let mut transform_seed = Vec::with_capacity(32);
    let mut encryption_iv = Vec::with_capacity(32);
    let mut transform_rounds = 0u64;
    let mut protected_stream_key = Vec::with_capacity(32);
    let mut stream_start_bytes = Vec::with_capacity(32);

    loop {
        let mut buf = [0u8; 3];

        if let Err(err) = db_file.read_exact(&mut buf[0..]) {
            return Err(KeepassLoadError::IO(err))
        }

        let field_id: FieldID = buf[0].try_into().unwrap(); // XXX don't unwrap!
        let field_length = u16::from_le_bytes(buf[1..3].try_into().unwrap()); // XXX this feels...wrong

        // XXX shorthand for combining these two?
        let mut field_data = Vec::with_capacity(field_length.into());
        field_data.resize(field_length.into(), 0);

        if let Err(err) = db_file.read_exact(field_data.as_mut_slice()) {
            return Err(KeepassLoadError::IO(err))
        }

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
                let compression_algorithm = u32::from_le_bytes(field_data.try_into().unwrap());
                if compression_algorithm != COMPRESSION_ALGORITHM_GZIP {
                    return Err(KeepassLoadError::UnsupportedCompressionAlgorithm);
                }
            },
            FieldID::MasterSeed => {
                // XXX check field length
                master_seed = field_data;
            },
            FieldID::TransformSeed => {
                // XXX check field length
                transform_seed = field_data;
            },
            FieldID::TransformRounds => {
                transform_rounds = u64::from_le_bytes(field_data.try_into().unwrap());
            },
            FieldID::EncryptionIV => {
                encryption_iv = field_data;
            },
            FieldID::ProtectedStreamKey => {
                // XXX check field length
                protected_stream_key = field_data;
            },
            FieldID::StreamStartBytes => {
                // XXX check field length
                stream_start_bytes = field_data;
            },
            FieldID::InnerRandomStreamID => {
                let stream_id = u32::from_le_bytes(field_data.try_into().unwrap());
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

    for _ in 0..transform_rounds {
        // XXX do I really need to recreate this over and over?
        let mut aes = aes::ecb_encryptor(aes::KeySize::KeySize256, &transform_seed, blockmodes::NoPadding);
        let mut this_rounds_output = [0u8; 32];
        aes.encrypt(&mut RefReadBuffer::new(&transformed_key), &mut RefWriteBuffer::new(&mut this_rounds_output), true).unwrap();
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
        hasher.input(&master_seed);
        hasher.input(&transformed_key);
        let mut hash: [u8; 32] = [0; 32];
        hasher.result(&mut hash);
        hash
    };

    // XXX I hate this reuse of aes
    let mut aes = aes::cbc_decryptor(aes::KeySize::KeySize256, &master_key, &encryption_iv, blockmodes::NoPadding);

    // XXX shitty error handling
    let mut cipher_text = Vec::new();
    db_file.read_to_end(&mut cipher_text).unwrap();

    let mut plain_text = Vec::new();
    let mut cipher_text_buffer = RefReadBuffer::new(&cipher_text);
    let mut work_space = [0; 4096];
    let mut plain_text_buffer = RefWriteBuffer::new(&mut work_space);

    loop {
        let res = aes.decrypt(&mut cipher_text_buffer, &mut plain_text_buffer, true).unwrap();
        plain_text.extend(plain_text_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match res {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => continue,
        }
    }

    let first_block_plaintext = &plain_text[..stream_start_bytes.len()];
    let mut remaining_plaintext = &plain_text[stream_start_bytes.len()..];

    if first_block_plaintext != stream_start_bytes {
        return Err(KeepassLoadError::StreamStartMismatch);
    }

    loop {
        let mut buf = [0u8; 4];
        remaining_plaintext.read_exact(&mut buf).unwrap();
        let block_id = u32::from_le_bytes(buf);

        let mut block_hash = [0u8; 32];
        remaining_plaintext.read_exact(&mut block_hash).unwrap();

        remaining_plaintext.read_exact(&mut buf).unwrap();
        let block_size = u32::from_le_bytes(buf);

        if block_size == 0 {
            if block_hash != [0u8; 32] {
                return Err(KeepassLoadError::InvalidFinalHash);
            }

            panic!("premature EOF");
        }

        // XXX I like the idea of a block returning an immutable variable for this...
        let mut block_data = Vec::with_capacity(block_size as usize);
        block_data.resize(block_size as usize, 0);

        remaining_plaintext.read_exact(&mut block_data).unwrap();

        let mut gunzip = GzDecoder::new(block_data.as_slice());
        let mut uncompressed = String::new();
        gunzip.read_to_string(&mut uncompressed).unwrap();

        let db: KeepassDatabase = quick_xml::de::from_str(&uncompressed).unwrap();

        let password_decryption_key = {
            let mut hasher = Sha256::new();
            hasher.input(&protected_stream_key);
            let mut hash: [u8; 32] = [0; 32];
            hasher.result(&mut hash);
            hash
        };

        return Ok(KeepassDatabase{Root: decrypt_passwords(&db.Root, password_decryption_key)});
    }
}

fn decrypt_passwords(group: &KeepassDatabaseGroup, key: [u8; 32]) -> KeepassDatabaseGroup {
    return KeepassDatabaseGroup{
        Name: group.Name.clone(),
        Groups: group.Groups.clone(),
        Entries: group.Entries.clone(),
    };
}

// XXX default parameter value for depth?
fn dump_database(g: &KeepassDatabaseGroup, depth: u8) {
    println!("{}{}", String::from("  ").repeat(depth as usize), g.Name);
    for subgroup in &g.Groups {
        dump_database(&subgroup, depth + 1);
    }
    for entry in &g.Entries {
        let mut name = String::new();
        let mut password = String::new();

        for kv in &entry.KeyValues {
            if kv.Key == "Title" {
                name = kv.Value.clone();
            }
            if kv.Key == "Password" {
                password = kv.Value.clone();
            }
        }

        if name != "" && password != "" {
            println!("{}  {} {}", String::from("  ").repeat(depth as usize), name, password);
        }
    }
}

fn main() {
    let args: Vec<_> = env::args().collect();

    let filename = match args.as_slice() {
        [_, filename, ..] => filename,
        _ => {
            eprintln!("usage: rs-keepass-diff [first kdbx] [second kdbx]");
            process::exit(1);
        },
    };

    let password = read_password();
    // XXX why doesn't this have to be `let mut f`?
    let f = File::open(filename).unwrap();
    // XXX defer f.close() ?
    let keepass_db = load_database(f, password).unwrap();

    dump_database(&keepass_db.Root, 0);

    println!("{:?}", keepass_db)
}
