use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::iter::FromIterator;
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

fn find_value<'a>(entry: &'a kdbx::KeepassDatabaseEntry, target_key: &'static str) -> Option<&'a str> {
    entry.key_values.iter().filter(|kdbx::KeeValuePair{key, ..}| key == target_key).next().map(|kdbx::KeeValuePair{value, ..}| value.as_str())
}

// XXX couldn't path have its own lifetime? Is there a situation in which that would make sense?
fn collect_entries<'a>(group: &'a kdbx::KeepassDatabaseGroup, accum: &mut Vec<(String, &'a kdbx::KeepassDatabaseEntry)>, path: Vec<&'a str>) {
    for subgroup in &group.groups {
        // XXX can I do this as a single expr?
        let mut subpath = path.clone();
        subpath.push(subgroup.name.as_str());
        collect_entries(&subgroup, accum, subpath);
    }

    for entry in &group.entries {
        let title = find_value(entry, "Title").unwrap(); // XXX handle properly
        let path = path.join("/") + "/" + &title;
        accum.push( (path, entry) );
    }
}

enum EntryOp<'a> {
    Added(&'a kdbx::KeepassDatabaseEntry),
    Deleted(&'a kdbx::KeepassDatabaseEntry),
    Changed(&'a kdbx::KeepassDatabaseEntry, &'a kdbx::KeepassDatabaseEntry),
}

fn entries_differ(a: &kdbx::KeepassDatabaseEntry, b: &kdbx::KeepassDatabaseEntry) -> bool {
    match (find_value(a, "Password"), find_value(b, "Password")) {
        (Some(password_a), Some(password_b)) => password_a != password_b, // XXX check more than this
        (None, None) => true,
        _ => false,
    }
}

// XXX variable names: before and after or old and new
fn diff_databases<'a>(db_one: &'a kdbx::KeepassDatabase, db_two: &'a kdbx::KeepassDatabase) -> Vec<EntryOp<'a>> {
    let mut db_one_entries = vec![];
    let mut db_two_entries = vec![];

    collect_entries(&db_one.root, &mut db_one_entries, vec![]);
    collect_entries(&db_two.root, &mut db_two_entries, vec![]);

    let entry_lookup_one: HashMap<String, &kdbx::KeepassDatabaseEntry> = HashMap::from_iter(db_one_entries.into_iter());
    let entry_lookup_two: HashMap<String, &kdbx::KeepassDatabaseEntry> = HashMap::from_iter(db_two_entries.into_iter());

    let mut diff = vec![];

    for (path, &entry_one) in &entry_lookup_one {
        match entry_lookup_two.get(path) {
            Some(entry_two) if entries_differ(entry_one, entry_two) => {
                diff.push(EntryOp::Changed(entry_one, entry_two));
            }
            None => {
                diff.push(EntryOp::Deleted(entry_one));
            }
            _ => (),
        }
    }

    for (path, &entry) in &entry_lookup_two {
        if entry_lookup_one.contains_key(path) {
            continue;
        }

        diff.push(EntryOp::Added(entry));
    }

    diff
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
    use crate::{diff_databases, find_value};

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

    #[test]
    fn correct_diffs() {
        let mut f = File::open("one.kdbx").unwrap();
        let db_one = kdbx::load_database(f, String::from("abc123")).unwrap();

        let mut f = File::open("two.kdbx").unwrap();
        let db_two = kdbx::load_database(f, String::from("abc123")).unwrap();

        let diff = diff_databases(&db_one, &db_two);

        /* Test
         *   Entry 'one' has two different passwords (one.kdbx is newer)
         *   Entry 'two' exists in one.kdbx, but not two.kdbx
         */
        assert_eq!(diff.len(), 2);
        // XXX better check
    }
}
