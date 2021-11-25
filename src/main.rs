use std::convert::{TryFrom, TryInto};
use std::env;
use std::io;
use std::io::Read;
use std::fs::File;
use std::process;

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
    "".to_string()
}

#[derive(Debug)]
enum KeepassLoadError {
    IO(io::Error),
    BadMagicSignature,
    BadFileVersion,
    UnsupportedCipher,
    UnsupportedCompressionAlgorithm,
    UnsupportedStreamAlgorithm,
    Unimplemented,
}

#[derive(Debug)]
struct KeepassDatabase {
    master_seed: [u8; 32],
    transform_seed: [u8; 32],
    encryption_iv: [u8; 16], // XXX I think the size depends on the cipher algorithm
    transform_rounds: u64,
    protected_stream_key: [u8; 32],
    stream_start_bytes: [u8; 32],
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

// XXX make it a Read or something
fn load_database(mut db_file: File, _password: String) -> Result<KeepassDatabase, KeepassLoadError> {
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

    Ok(KeepassDatabase{
        master_seed: master_seed.try_into().unwrap(),
        transform_seed: transform_seed.try_into().unwrap(),
        encryption_iv: encryption_iv.try_into().unwrap(),
        transform_rounds: transform_rounds,
        protected_stream_key: protected_stream_key.try_into().unwrap(),
        stream_start_bytes: stream_start_bytes.try_into().unwrap(),
    })
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
    let keepass_db = load_database(f, password);

    println!("{:?}", keepass_db)
}
