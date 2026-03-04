pub struct Category {
    pub name: String,
}

pub struct Transaction {
    pub id: String,
    pub amount: i64,
    pub category: String,
    pub timestamp: i64,
    pub note: Option<String>,
}
