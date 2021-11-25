use std::env;
use std::io;
use std::io::Read;
use std::fs::File;
use std::process;

fn read_password() -> String {
    "".to_string()
}

#[derive(Debug)]
enum KeepassLoadError {
    IO(io::Error),
}

#[derive(Debug)]
struct KeepassDatabase {
}

// XXX make it a Read or something
fn load_database(mut db_file: File, _password: String) -> Result<KeepassDatabase, KeepassLoadError> {
    let mut buf: [u8; 4] = [0, 0, 0, 0]; // XXX why do I have to initialize this? b/c rust isn't smart enough to know that `read` will blow it away?

    // XXX there has to be a way to improve this
    if let Err(err) = db_file.read_exact(&mut buf) {
        return Err(KeepassLoadError::IO(err))
    }

    println!("{:?}", buf);

    Ok(KeepassDatabase{})
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
