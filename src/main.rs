use std::env;
use std::fs::File;
use std::process;

mod kdbx;

// XXX break this out into its own file/module/library/package/crate/whatever
fn read_password() -> String {
    "abc123".to_string()
}

// XXX default parameter value for depth?
fn dump_database(g: &kdbx::KeepassDatabaseGroup, depth: u8) {
    println!("{}{}", String::from("  ").repeat(depth as usize), g.name);
    for subgroup in &g.groups {
        dump_database(&subgroup, depth + 1);
    }
    for entry in &g.entries {
        let mut name = &String::new();
        let mut password = &String::new();

        for kv in &entry.key_values {
            if kv.key == "Title" {
                name = &kv.value;
            }
            if kv.key == "Password" {
                password = &kv.value;
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
    let keepass_db = kdbx::load_database(f, password).unwrap();

    dump_database(&keepass_db.root, 0);

    println!("{:?}", keepass_db)
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;
    
    use crate::kdbx::{self, KeepassDatabase, KeepassDatabaseEntry, KeepassLoadError};

    fn find_entry(db: &KeepassDatabase, path: &'static str) -> Option<KeepassDatabaseEntry> {
        let mut g = &db.root;
        let mut path_pieces = path.split('/').map(String::from).collect::<Vec<String>>();

        path_pieces.insert(0, String::from("Root"));

        'outerLoop:
        // XXX is there a better syntax here for "all but the last"?
        for name in &path_pieces[..path_pieces.len()-1] {
            for subgroup in &g.groups {
                if name == &subgroup.name {
                    g = subgroup;
                    continue 'outerLoop;
                }
            }

            return None;
        }

        let entry_name = &path_pieces[path_pieces.len()-1];
        for entry in &g.entries {
            match find_value(&entry, "Title") {
                Some(name) if &name == entry_name => { return Some(entry.clone()); },
                _ => (),
            }
        }
        None
    }

    // XXX using &str would be cool, but I need to learn lifetimes
    fn find_value(entry: &KeepassDatabaseEntry, key: &'static str) -> Option<String> {
        // XXX use iter method
        // XXX can I destructure here?
        for kv_pair in &entry.key_values {
            if kv_pair.key == key {
                return Some(kv_pair.value.clone());
            }
        }

        None
    }

    #[test]
    fn valid_kdbx_file() {
        let f = File::open("one.kdbx").unwrap();
        let _ = kdbx::load_database(f, String::from("abc123")).unwrap();
    }

    #[test]
    fn test_entries_are_present() {
        let f = File::open("one.kdbx").unwrap();
        let db = kdbx::load_database(f, String::from("abc123")).unwrap();

        let entry_one = find_entry(&db, "Test/one").unwrap();
        let entry_two = find_entry(&db, "Test/two").unwrap();
        let entry_three = find_entry(&db, "Test/three").unwrap();

        assert_eq!(find_value(&entry_one, "Password").unwrap(), "fUBH7WxV8O9sBhvh");
        assert_eq!(find_value(&entry_two, "Password").unwrap(), "RtT4godVcetADfvz");
        assert_eq!(find_value(&entry_three, "Password").unwrap(), "eMjUwPLadNQeniIl");
    }

    #[test]
    fn invalid_magic_signature() {
        let mut f = File::open("one.kdbx").unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();

        buf[0] += 1;

        let res = kdbx::load_database(buf.as_slice(), String::from("abc123"));

        match res {
            Err(KeepassLoadError::BadMagicSignature) => {},
            _ => panic!("Expected BadMagicSignature, got {:?}", res),
        }
    }

    #[test]
    fn invalid_version() {
        let mut f = File::open("one.kdbx").unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();

        buf[10] = 4;

        let res = kdbx::load_database(buf.as_slice(), String::from("abc123"));

        match res {
            Err(KeepassLoadError::BadFileVersion) => {},
            _ => panic!("Expected BadFileVersion, got {:?}", res),
        }
    }

    #[test]
    fn invalid_cipher() {
        let mut f = File::open("one.kdbx").unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();

        buf[15] += 1;

        let res = kdbx::load_database(buf.as_slice(), String::from("abc123"));

        match res {
            Err(KeepassLoadError::UnsupportedCipher) => {},
            _ => panic!("Expected UnsupportedCipher, got {:?}", res),
        }
    }

    #[test]
    fn invalid_compression_algorithm() {
        let mut f = File::open("one.kdbx").unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();

        buf[34] += 1;

        let res = kdbx::load_database(buf.as_slice(), String::from("abc123"));

        match res {
            Err(KeepassLoadError::UnsupportedCompressionAlgorithm) => {},
            _ => panic!("Expected UnsupportedCompressionAlgorithm, got {:?}", res),
        }
    }

    #[test]
    fn invalid_stream_algorithm() {
        let mut f = File::open("one.kdbx").unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();

        buf[211] += 1;

        let res = kdbx::load_database(buf.as_slice(), String::from("abc123"));

        match res {
            Err(KeepassLoadError::UnsupportedStreamAlgorithm) => {},
            _ => panic!("Expected UnsupportedStreamAlgorithm, got {:?}", res),
        }
    }

    #[test]
    fn stream_start_mismatch() {
        let mut f = File::open("one.kdbx").unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();

        buf[176] += 1;

        let res = kdbx::load_database(buf.as_slice(), String::from("abc123"));

        match res {
            Err(KeepassLoadError::StreamStartMismatch) => {},
            _ => panic!("Expected StreamStartMismatch, got {:?}", res),
        }
    }

    #[test]
    fn invalid_field_id() {
        let mut f = File::open("one.kdbx").unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();

        buf[73] = 15;

        let res = kdbx::load_database(buf.as_slice(), String::from("abc123"));

        match res {
            Err(KeepassLoadError::InvalidFieldID) => {},
            _ => panic!("Expected InvalidFieldID, got {:?}", res),
        }
    }
}
