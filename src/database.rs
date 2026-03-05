use crate::models::Transaction;
use rusqlite::{Connection, Result, params};

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use zeroize::Zeroize;

pub struct AegisDB {
    conn: Connection,
}

struct SecretGuard<'a>(&'a mut String);

impl Drop for SecretGuard<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug)]
pub enum DBError {
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

impl AegisDB {
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

    pub fn init(&self) -> Result<()> {
        self.conn.execute("PRAGMA foreign_keys = ON", ())?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS categories (
                name TEXT PRIMARY KEY
            )",
            (),
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS transactions (
                id          TEXT PRIMARY KEY,
                amount      INTEGER NOT NULL,
                category    TEXT NOT NULL,
                timestamp   INTEGER NOT NULL,
                note        TEXT,
                FOREIGN KEY (category) REFERENCES categories (name)
            )",
            (),
        )?;

        Ok(())
    }

    // ==========================================
    // Categories CURD
    // ==========================================

    pub fn add_category(&self, name: &str) -> Result<()> {
        self.conn
            .execute("INSERT INTO categories (name) VALUES (?1)", params![name])?;
        Ok(())
    }

    pub fn get_categories(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name FROM categories ORDER BY name")?;
        let categories = stmt
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        Ok(categories)
    }

    pub fn delete_category(&self, name: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM categories WHERE name = ?1", params![name])?;
        Ok(())
    }

    pub fn update_category(&mut self, old_name: &str, new_name: &str) -> Result<()> {
        let tx = self.conn.transaction()?;

        tx.execute(
            "INSERT INTO categories (name) VALUES (?1)",
            params![new_name],
        )?;
        tx.execute(
            "UPDATE transactions SET category = ?1 WHERE category = ?2",
            params![new_name, old_name],
        )?;
        tx.execute("DELETE FROM categories WHERE name = ?1", params![old_name])?;

        tx.commit()?;
        Ok(())
    }

    // ==========================================
    // Transactions CRUD
    // ==========================================

    pub fn add_transaction(&self, tx: &Transaction) -> Result<()> {
        self.conn.execute(
            "INSERT INTO transactions (id, amount, category, timestamp, note)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![tx.id, tx.amount, tx.category, tx.timestamp, tx.note],
        )?;
        Ok(())
    }

    pub fn get_transaction(&self, id: &str) -> Result<Option<Transaction>> {
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

    pub fn update_transaction(&self, tx: &Transaction) -> Result<()> {
        self.conn.execute(
            "UPDATE transactions 
             SET amount = ?1, category = ?2, timestamp = ?3, note = ?4 
             WHERE id = ?5",
            params![tx.amount, tx.category, tx.timestamp, tx.note, tx.id],
        )?;
        Ok(())
    }

    pub fn delete_transaction(&self, id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM transactions WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ==========================================
    // Utilities
    // ==========================================

    pub fn get_all_transactions(&self) -> Result<Vec<Transaction>> {
        self.query_transactions("SELECT id, amount, category, timestamp, note FROM transactions ORDER BY timestamp DESC",[])
    }

    pub fn get_transactions_by_category(&self, category: &str) -> Result<Vec<Transaction>> {
        let sql = "SELECT id, amount, category, timestamp, note
                    FROM transactions
                    WHERE category = ?1
                    ORDER BY timestamp DESC";
        self.query_transactions(sql, params![category])
    }

    pub fn get_transactions_in_range(
        &self,
        start_ts: i64,
        end_ts: i64,
    ) -> Result<Vec<Transaction>> {
        let sql = "SELECT id, amount, category, timestamp, note
                    FROM transactions
                    WHERE timestamp >= ?1
                    AND timestamp <= ?2
                    ORDER BY timestamp DESC";
        self.query_transactions(sql, params![start_ts, end_ts])
    }

    pub fn get_transactions_by_category_and_range(
        &self,
        category: &str,
        start_ts: i64,
        end_ts: i64,
    ) -> Result<Vec<Transaction>> {
        let sql = "SELECT id, amount, category, timestamp, note 
                   FROM transactions 
                   WHERE category = ?1 
                   AND timestamp >= ?2 
                   AND timestamp <= ?3 
                   ORDER BY timestamp DESC";

        self.query_transactions(sql, params![category, start_ts, end_ts])
    }

    pub fn get_total_amount_in_range(&self, start_ts: i64, end_ts: i64) -> Result<i64> {
        let mut stmt = self.conn.prepare(
            "SELECT COALESCE(SUM(amount), 0) FROM transactions
                WHERE timestamp >= ?1 AND timestamp <= ?2",
        )?;
        let total: i64 = stmt.query_row(params![start_ts, end_ts], |row| row.get(0))?;
        Ok(total)
    }

    pub fn get_total_amount_by_category(&self, category: &str) -> Result<i64> {
        let mut stmt = self
            .conn
            .prepare("SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE category = ?1")?;
        let total: i64 = stmt.query_row(params![category], |row| row.get(0))?;
        Ok(total)
    }

    pub fn get_total_amount_by_category_and_range(
        &self,
        category: &str,
        start_ts: i64,
        end_ts: i64,
    ) -> Result<i64> {
        let mut stmt = self.conn.prepare(
            "SELECT COALESCE(SUM(amount), 0) 
             FROM transactions 
             WHERE category = ?1 
             AND timestamp >= ?2 
             AND timestamp <= ?3",
        )?;

        let total: i64 = stmt.query_row(params![category, start_ts, end_ts], |row| row.get(0))?;

        Ok(total)
    }

    fn query_transactions<P>(&self, sql: &str, params: P) -> Result<Vec<Transaction>>
    where
        P: rusqlite::Params,
    {
        let mut stmt = self.conn.prepare(sql)?;
        let tx_iter = stmt.query_map(params, |row| {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(password: &mut String) -> AegisDB {
        AegisDB::new(":memory:", password, "VTVZeW1abDM3QW00OEkwcTRw")
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

        storage
            .add_category("Food")
            .expect("Failed to add category");

        storage
            .add_transaction(&tx)
            .expect("Failed to add transaction");

        let retrieved = storage
            .get_transaction("tx_123")
            .expect("Failed to get transaction");
        assert!(retrieved.is_some(), "Transaction should exist");

        let retrieved_tx = retrieved.unwrap();
        assert_eq!(retrieved_tx.id, tx.id);
        assert_eq!(retrieved_tx.amount, tx.amount);
        assert_eq!(retrieved_tx.category, tx.category);
        assert_eq!(retrieved_tx.timestamp, tx.timestamp);
        assert_eq!(retrieved_tx.note, tx.note);
    }

    #[test]
    fn test_foreign_key_constraint() {
        let mut password = String::from("test_pass");
        let storage = setup(&mut password);
        let tx = Transaction {
            id: "tx_err".to_string(),
            amount: 500,
            category: "UnknownCategory".to_string(),
            timestamp: 1672531200,
            note: None,
        };

        let result = storage.add_transaction(&tx);
        assert!(result.is_err(), "Should fail due to foreign key constraint");
    }

    #[test]
    fn test_update_and_delete() {
        let mut password = String::from("jU68MR2vyIO0vFikfvgw");
        let mut storage = setup(&mut password);

        storage.add_category("Transport").unwrap();
        let mut tx = Transaction {
            id: "tx_2".to_string(),
            amount: 200,
            category: "Transport".to_string(),
            timestamp: 1000,
            note: None,
        };
        storage.add_transaction(&tx).unwrap();

        tx.amount = 300;
        tx.note = Some("Bus ticket".to_string());
        storage.update_transaction(&tx).unwrap();

        let updated_tx = storage.get_transaction("tx_2").unwrap().unwrap();
        assert_eq!(updated_tx.amount, 300);
        assert_eq!(updated_tx.note, Some("Bus ticket".to_string()));

        storage.update_category("Transport", "Commute").unwrap();
        let migrated_tx = storage.get_transaction("tx_2").unwrap().unwrap();
        assert_eq!(migrated_tx.category, "Commute");

        storage.delete_transaction("tx_2").unwrap();
        let deleted_tx = storage.get_transaction("tx_2").unwrap();
        assert!(deleted_tx.is_none());
    }

    #[test]
    fn test_statistics_and_queries() {
        let mut password = String::from("jU68MR2vyIO0vFikfvgw");
        let storage = setup(&mut password);

        storage.add_category("Food").unwrap();
        storage.add_category("Salary").unwrap();

        storage
            .add_transaction(&Transaction {
                id: "t1".to_string(),
                amount: -50,
                category: "Food".to_string(),
                timestamp: 100,
                note: None,
            })
            .unwrap();
        storage
            .add_transaction(&Transaction {
                id: "t2".to_string(),
                amount: -150,
                category: "Food".to_string(),
                timestamp: 200,
                note: None,
            })
            .unwrap();
        storage
            .add_transaction(&Transaction {
                id: "t3".to_string(),
                amount: 5000,
                category: "Salary".to_string(),
                timestamp: 150,
                note: None,
            })
            .unwrap();

        let food_txs = storage.get_transactions_by_category("Food").unwrap();
        assert_eq!(food_txs.len(), 2);

        let range_txs = storage.get_transactions_in_range(100, 150).unwrap();
        assert_eq!(range_txs.len(), 2);

        let food_total = storage.get_total_amount_by_category("Food").unwrap();
        assert_eq!(food_total, -200); // -50 + -150

        let range_total = storage.get_total_amount_in_range(100, 200).unwrap();
        assert_eq!(range_total, 4800); // -50 + -150 + 5000
    }

    #[test]
    fn test_utilities() {
        let mut password = String::from("jU68MR2vyIO0vFikfvgw");
        let storage = setup(&mut password);

        storage
            .add_category("Food")
            .expect("Failed to add category");
        storage
            .add_category("Tech")
            .expect("Failed to add category");

        let tx1 = Transaction {
            id: "tx_1".to_string(),
            amount: 500,
            category: "Food".to_string(),
            timestamp: 1000,
            note: Some("Lunch".to_string()),
        };
        let tx2 = Transaction {
            id: "tx_2".to_string(),
            amount: 1500,
            category: "Food".to_string(),
            timestamp: 2000,
            note: Some("Dinner".to_string()),
        };
        let tx3 = Transaction {
            id: "tx_3".to_string(),
            amount: 3000,
            category: "Tech".to_string(),
            timestamp: 1500,
            note: Some("Mouse".to_string()),
        };

        for tx in &[&tx1, &tx2, &tx3] {
            storage
                .add_transaction(tx)
                .expect("Failed to add transaction");
        }

        let list = storage
            .get_transactions_by_category_and_range("Food", 500, 2500)
            .expect("Query list failed");

        assert_eq!(list.len(), 2, "Should find exactly 2 transactions");
        assert!(list.iter().any(|t| t.id == "tx_1"));
        assert!(list.iter().any(|t| t.id == "tx_2"));

        let total = storage
            .get_total_amount_by_category_and_range("Food", 1500, 2500)
            .expect("Query total failed");

        assert_eq!(total, 1500, "Total amount should match tx2 only");

        let empty_total = storage
            .get_total_amount_by_category_and_range("Food", 5000, 6000)
            .expect("Query empty range failed");

        assert_eq!(empty_total, 0, "Total should be 0 for empty results");
    }
}
