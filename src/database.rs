use crate::models::Transaction;
use rusqlite::{Connection, Result, params};

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use zeroize::Zeroize;

struct TransactionDB {
    conn: Connection,
}

struct SecretGuard<'a>(&'a mut String);

impl Drop for SecretGuard<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug)]
enum DBError {
    SaltError(String),
    HashError(String),
    SQLError(rusqlite::Error),
}

impl From<rusqlite::Error> for DBError {
    fn from(e: rusqlite::Error) -> Self {
        DBError::SQLError(e)
    }
}

impl std::fmt::Display for DBError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DBError::SaltError(e) => write!(f, "salt error: {}", e),
            DBError::HashError(e) => write!(f, "hash password error: {}", e),
            DBError::SQLError(e) => write!(f, "rusqlite error: {}", e),
        }
    }
}

impl TransactionDB {
    pub fn new(path: &str, raw_input: &mut String, salt: &str) -> Result<Self, DBError> {
        // Using Argon2id algorithmic variants by default
        let _password_guard = SecretGuard(raw_input);

        let argon2 = Argon2::default();
        let salt_obj = SaltString::from_b64(salt)
            .map_err(|e| DBError::SaltError(format!("invalid salt format: {}", e)))?;
        let password_hash = argon2
            .hash_password(_password_guard.0.as_bytes(), &salt_obj)
            .map_err(|e| DBError::HashError(format!("failed to compute password hash: {}", e)))?;

        let hash_output = password_hash.hash.ok_or_else(|| {
            DBError::HashError("failed to extract output bytes from hash".to_string())
        })?;
        let mut derived_key = hash_output.as_bytes().to_vec();
        let hex_key = format!("x'{}'", hex::encode(&derived_key));

        let conn = Connection::open(path)?;
        conn.pragma_update(None, "KEY", &hex_key)?;
        derived_key.zeroize();

        let db = Self { conn };
        db.init()?;
        Ok(db)
    }

    fn init(&self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS transactions (
            id          TEXT PRIMARY KEY,
            amount      INTEGER NOT NULL,
            category    TEXT NOT NULL,
            timestamp   INTEGER NOT NULL,
            note        TEXT
        )",
            (),
        )?;
        Ok(())
    }

    pub fn add_transaction(&self, transaction: &Transaction) -> Result<()> {
        self.conn.execute(
            "INSERT INTO transactions (id, amount, category, timestamp, note)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                &transaction.id,
                transaction.amount,
                &transaction.category,
                transaction.timestamp,
                &transaction.note,
            ),
        )?;
        Ok(())
    }

    pub fn get_by_id(&self, id: &str) -> Result<Option<Transaction>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, amount, category, timestamp, note FROM transactions WHERE id = ?1",
        )?;

        let mut rows = stmt.query([id])?;

        if let Some(row) = rows.next()? {
            Ok(Some(Transaction {
                id: row.get(0)?,
                amount: row.get(1)?,
                category: row.get(2)?,
                timestamp: row.get(3)?,
                note: row.get(4)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_all(&self) -> Result<Vec<Transaction>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, amount, category, timestamp, note FROM transactions")?;

        let tx_iter = stmt.query_map([], |row| {
            Ok(Transaction {
                id: row.get(0)?,
                amount: row.get(1)?,
                category: row.get(2)?,
                timestamp: row.get(3)?,
                note: row.get(4)?,
            })
        })?;

        tx_iter.collect()
    }

    pub fn update_transaction(&self, transaction: &Transaction) -> Result<()> {
        self.conn.execute(
            "UPDATE transactions 
             SET amount = ?1, category = ?2, timestamp = ?3, note = ?4 
             WHERE id = ?5",
            params![
                transaction.amount,
                transaction.category,
                transaction.timestamp,
                transaction.note,
                transaction.id
            ],
        )?;
        Ok(())
    }

    pub fn delete_transaction(&self, id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM transactions WHERE id = ?1", [id])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(password: &mut String) -> TransactionDB {
        TransactionDB::new(":memory:", password, "VTVZeW1abDM3QW00OEkwcTRw")
            .expect("Failed to create in-memory database")
    }

    #[test]
    fn test_create_and_get() {
        let mut password = String::from("jU68MR2vyIO0vFikfvgw");
        let storage = setup(&mut password);
        let tx = Transaction {
            id: "tx_123".to_string(),
            amount: 1000,
            category: "Food".to_string(),
            timestamp: 1672531200,
            note: Some("Delicious Ramen".to_string()),
        };

        storage.add_transaction(&tx).unwrap();

        let retrieved = storage
            .get_by_id("tx_123")
            .unwrap()
            .expect("Should find tx");
        assert_eq!(retrieved.id, "tx_123");
        assert_eq!(retrieved.amount, 1000);
        assert_eq!(retrieved.note, Some("Delicious Ramen".to_string()));
    }

    #[test]
    fn test_update() {
        let mut password = String::from("jU68MR2vyIO0vFikfvgw");
        let storage = setup(&mut password);
        let mut tx = Transaction {
            id: "tx_1".to_string(),
            amount: 50,
            category: "Transport".to_string(),
            timestamp: 100,
            note: None,
        };
        storage.add_transaction(&tx).unwrap();

        tx.amount = 75;
        tx.note = Some("Taxi fare".to_string());
        storage.update_transaction(&tx).unwrap();

        let updated = storage.get_by_id("tx_1").unwrap().unwrap();
        assert_eq!(updated.amount, 75);
        assert_eq!(updated.note, Some("Taxi fare".to_string()));
    }

    #[test]
    fn test_delete() {
        let mut password = String::from("jU68MR2vyIO0vFikfvgw");
        let storage = setup(&mut password);
        let tx = Transaction {
            id: "del_me".to_string(),
            amount: 10,
            category: "Misc".to_string(),
            timestamp: 200,
            note: None,
        };
        storage.add_transaction(&tx).unwrap();

        assert!(storage.get_by_id("del_me").unwrap().is_some());

        storage.delete_transaction("del_me").unwrap();

        assert!(storage.get_by_id("del_me").unwrap().is_none());
    }

    #[test]
    fn test_get_all() {
        let mut password = String::from("jU68MR2vyIO0vFikfvgw");
        let storage = setup(&mut password);
        let tx1 = Transaction {
            id: "1".into(),
            amount: 10,
            category: "A".into(),
            timestamp: 1,
            note: None,
        };
        let tx2 = Transaction {
            id: "2".into(),
            amount: 20,
            category: "B".into(),
            timestamp: 2,
            note: None,
        };

        storage.add_transaction(&tx1).unwrap();
        storage.add_transaction(&tx2).unwrap();

        let all = storage.get_all().unwrap();
        assert_eq!(all.len(), 2);
    }
}
