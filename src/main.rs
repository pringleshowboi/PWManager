use ring::aead::{Aad, BoundKey, Nonce, UnboundKey, AES_256_GCM, LessSafeKey};
use ring::rand::{SecureRandom, SystemRandom};
use rpassword::read_password;
use rusqlite::{params, Connection, Result};
use std::io::{self, Write};

fn generate_key() -> Vec<u8> {
    let rng = SystemRandom::new();
    let mut key = vec![0u8; 32]; // 256-bit AES key
    rng.fill(&mut key).unwrap();
    key
}

fn encrypt_password(password: &str, key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12]; // 96-bit nonce
    rng.fill(&mut nonce_bytes).unwrap();

    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = password.as_bytes().to_vec();
    let unbound_key = UnboundKey::new(&AES_256_GCM, key).unwrap();
    let less_safe_key = LessSafeKey::new(unbound_key);

    less_safe_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .unwrap();

    (nonce_bytes.to_vec(), in_out)
}

fn decrypt_password(nonce_bytes: &[u8], encrypted: &[u8], key: &[u8]) -> Result<String, String> {
    let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().unwrap());
    let mut in_out = encrypted.to_vec();
    let unbound_key = UnboundKey::new(&AES_256_GCM, key).unwrap();
    let less_safe_key = LessSafeKey::new(unbound_key);

    match less_safe_key.open_in_place(nonce, Aad::empty(), &mut in_out) {
        Ok(plaintext) => match String::from_utf8(plaintext.to_vec()) {
            Ok(text) => Ok(text),
            Err(_) => Err("Decryption successful, but failed to decode UTF-8.".to_string()),
        },
        Err(_) => Err("Decryption failed! Incorrect key or corrupted data.".to_string()),
    }
}

fn setup_database() -> Result<Connection> {
    let conn = Connection::open("passwords.db")?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            service TEXT NOT NULL UNIQUE,
            nonce BLOB NOT NULL,
            encrypted_password BLOB NOT NULL
        )",
        [],
    )?;
    Ok(conn)
}

fn store_password(conn: &Connection, service: &str, nonce: &[u8], encrypted: &[u8]) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO passwords (service, nonce, encrypted_password) VALUES (?1, ?2, ?3)",
        params![service, nonce, encrypted],
    )?;
    Ok(())
}

fn retrieve_password(conn: &Connection, service: &str, key: &[u8]) -> Result<Option<String>> {
    let mut stmt = conn.prepare("SELECT nonce, encrypted_password FROM passwords WHERE service = ?1")?;
    let mut rows = stmt.query(params![service])?;

    if let Some(row) = rows.next()? {
        let nonce: Vec<u8> = row.get(0)?;
        let encrypted: Vec<u8> = row.get(1)?;
        match decrypt_password(&nonce, &encrypted, key) {
            Ok(password) => Ok(Some(password)),
            Err(err) => {
                println!("Error decrypting: {}", err);
                Ok(None)
            }
        }
    } else {
        Ok(None)
    }
}

fn list_services(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("SELECT service FROM passwords")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    println!("\nStored services:");
    for service in rows {
        println!("- {}", service?);
    }
    println!();
    Ok(())
}

fn delete_password(conn: &Connection, service: &str) -> Result<()> {
    conn.execute("DELETE FROM passwords WHERE service = ?1", params![service])?;
    println!("Deleted password for '{}'.", service);
    Ok(())
}

fn main() -> Result<()> {
    let key = generate_key();
    let conn = setup_database()?;

    loop {
        println!("\nPassword Manager Menu:");
        println!("1. Store a password");
        println!("2. Retrieve a password");
        println!("3. View all stored services");
        println!("4. Delete a password");
        println!("5. Exit");

        print!("Choose an option: ");
        io::stdout().flush().unwrap();
        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();

        match choice.trim() {
            "1" => {
                print!("Enter the service name: ");
                io::stdout().flush().unwrap();
                let mut service = String::new();
                io::stdin().read_line(&mut service).unwrap();
                let service = service.trim();

                print!("Enter a password to store: ");
                io::stdout().flush().unwrap();
                let password = read_password().unwrap();

                let (nonce, encrypted) = encrypt_password(&password, &key);
                store_password(&conn, service, &nonce, &encrypted)?;
                println!("Password stored successfully!");
            }
            "2" => {
                print!("Enter the service name to retrieve: ");
                io::stdout().flush().unwrap();
                let mut service = String::new();
                io::stdin().read_line(&mut service).unwrap();
                let service = service.trim();

                match retrieve_password(&conn, service, &key)? {
                    Some(password) => println!("Decrypted password: {}", password),
                    None => println!("No password found for '{}'", service),
                }
            }
            "3" => {
                list_services(&conn)?;
            }
            "4" => {
                print!("Enter the service name to delete: ");
                io::stdout().flush().unwrap();
                let mut service = String::new();
                io::stdin().read_line(&mut service).unwrap();
                let service = service.trim();

                delete_password(&conn, service)?;
            }
            "5" => {
                println!("Exiting...");
                break;
            }
            _ => println!("Invalid option, please try again."),
        }
    }

    Ok(())
}
