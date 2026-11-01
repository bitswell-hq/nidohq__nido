//! Result files: pretty JSON, and CSV for flat rows.

use std::path::Path;

use serde::Serialize;
use serde_json::Value;

/// Write `value` as pretty JSON to `dir/name`.
///
/// # Errors
///
/// If the file cannot be written.
pub fn write<T: Serialize + ?Sized>(dir: &Path, name: &str, value: &T) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join(name);
    let mut text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    text.push('\n');
    std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Write rows of flat objects as CSV to `dir/name`, columns in the first
/// row's field order.
///
/// # Errors
///
/// If the rows are not flat objects or the file cannot be written.
pub fn write_csv<T: Serialize>(dir: &Path, name: &str, rows: &[T]) -> Result<(), String> {
    let rows: Vec<Value> = rows
        .iter()
        .map(|r| serde_json::to_value(r).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let Some(Value::Object(first)) = rows.first() else {
        return Err(format!("{name}: no rows"));
    };
    let columns: Vec<String> = first.keys().cloned().collect();
    let mut text = columns.join(",");
    text.push('\n');
    for row in &rows {
        let cells: Vec<String> = columns
            .iter()
            .map(|c| match row.get(c) {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Null) | None => String::new(),
                Some(v) => v.to_string(),
            })
            .collect();
        text.push_str(&cells.join(","));
        text.push('\n');
    }
    let path = dir.join(name);
    std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Read `dir/name` as JSON.
///
/// # Errors
///
/// If the file cannot be read or parsed.
pub fn read(dir: &Path, name: &str) -> Result<Value, String> {
    let path = dir.join(name);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}
