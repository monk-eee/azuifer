//! Tests of projection, filtering, JSON paths, aggregates and error classes.

use super::*;

fn csv(fields: &[&str]) -> Row {
    Row::Csv(fields.iter().map(|field| (*field).to_owned()).collect())
}

fn select(sql: &str, row: &Row, headers: Option<&[String]>) -> Vec<(String, Value)> {
    let query = Query::parse(sql).unwrap();
    let scope = Scope { headers };
    assert!(query.matches(row, &scope).unwrap(), "{sql}");
    query.project(row, &scope).unwrap()
}

fn passes(sql: &str, row: &Row) -> bool {
    Query::parse(sql)
        .unwrap()
        .matches(row, &Scope { headers: None })
        .unwrap()
}

#[test]
fn positional_and_named_columns_project_in_order() {
    let row = csv(&["ann", "31", "NZ"]);
    let headers = ["name".to_owned(), "age".to_owned(), "country".to_owned()];
    let positional = select("SELECT _3, _1 FROM BlobStorage", &row, None);
    assert_eq!(positional[0], ("_3".into(), Value::Str("NZ".into())));
    assert_eq!(positional[1].1, Value::Str("ann".into()));
    let named = select(
        "select s.name as who, AGE from BlobStorage s",
        &row,
        Some(&headers),
    );
    assert_eq!(named[0], ("who".into(), Value::Str("ann".into())));
    assert_eq!(named[1], ("AGE".into(), Value::Str("31".into())));
    assert_eq!(
        select("SELECT * FROM BlobStorage", &row, Some(&headers)).len(),
        3
    );
}

#[test]
fn where_compares_numbers_and_text_with_three_valued_logic() {
    let row = csv(&["ann", "31", ""]);
    assert!(passes(
        "SELECT * FROM BlobStorage WHERE _2 > 30 AND _1 = 'ann'",
        &row
    ));
    assert!(passes(
        "SELECT * FROM BlobStorage WHERE CAST(_2 AS INT) + 1 = 32",
        &row
    ));
    assert!(!passes("SELECT * FROM BlobStorage WHERE _4 = 'x'", &row));
    assert!(!passes(
        "SELECT * FROM BlobStorage WHERE NOT (_4 = 'x')",
        &row
    ));
    assert!(passes(
        "SELECT * FROM BlobStorage WHERE _4 IS NULL OR _2 < 3",
        &row
    ));
    assert!(passes(
        "SELECT * FROM BlobStorage WHERE _1 LIKE 'a_n' AND _1 NOT LIKE 'b%'",
        &row
    ));
    assert!(passes(
        "SELECT * FROM BlobStorage WHERE _2 BETWEEN 30 AND 40 AND _1 IN ('bob', 'ann')",
        &row
    ));
    assert!(passes(
        "SELECT * FROM BlobStorage WHERE UPPER(_1) || '!' = 'ANN!' AND CHAR_LENGTH(_1) = 3",
        &row
    ));
    assert!(passes(
        "SELECT * FROM BlobStorage WHERE SUBSTRING(_1, 2, 2) = 'nn'",
        &row
    ));
}

#[test]
fn json_paths_reach_nested_fields_and_array_items() {
    let row = Row::Json(serde_json::json!({"a": {"b": [10, 20]}, "name": "x"}));
    let query =
        Query::parse("SELECT s.a.b[1] AS second, name FROM BlobStorage s WHERE s.a.b[0] = 10")
            .unwrap();
    let scope = Scope { headers: None };
    assert!(query.matches(&row, &scope).unwrap());
    let out = query.project(&row, &scope).unwrap();
    assert_eq!(out[0], ("second".into(), Value::Int(20)));
    assert_eq!(out[1], ("name".into(), Value::Str("x".into())));
}

#[test]
fn aggregates_fold_matching_rows() {
    let query =
        Query::parse("SELECT COUNT(*) AS n, SUM(_1), AVG(_1), MIN(_1), MAX(_1) FROM BlobStorage")
            .unwrap();
    assert!(query.is_aggregate());
    let scope = Scope { headers: None };
    let mut accumulators = query.accumulators();
    for value in ["3", "5", "10"] {
        query
            .accumulate(&mut accumulators, &csv(&[value]), &scope)
            .unwrap();
    }
    let results: Vec<Value> = accumulators.into_iter().map(Accumulator::finish).collect();
    assert_eq!(results[0], Value::Int(3));
    assert_eq!(results[1], Value::Int(18));
    assert_eq!(results[2], Value::Float(6.0));
    // Text compares as text: no cast, no numeric order.
    assert_eq!(results[3], Value::Str("10".into()));
    assert_eq!(results[4], Value::Str("5".into()));
    assert_eq!(query.aggregate_names()[0], "n");
}

#[test]
fn bad_sql_is_a_parse_error_and_bad_casts_fail_at_run_time() {
    for sql in [
        "SELECT FROM BlobStorage",
        "SELECT * FROM other",
        "SELECT * FROM BlobStorage WHERE",
        "SELECT * FROM BlobStorage WHERE _1 = 'a",
        "SELECT COUNT(*), _1 FROM BlobStorage",
        "SELECT * FROM BlobStorage WHERE SUM(_1) > 1",
        "SELECT nosuch(_1) FROM BlobStorage",
        "SELECT * FROM BlobStorage LIMIT x",
    ] {
        assert_eq!(Query::parse(sql).unwrap_err().name, "ParseError", "{sql}");
    }
    let query = Query::parse("SELECT CAST(_1 AS INT) FROM BlobStorage").unwrap();
    let error = query
        .project(&csv(&["abc"]), &Scope { headers: None })
        .unwrap_err();
    assert_eq!(error.name, "InvalidTypeConversion");
    assert!(!error.fatal);
    let query = Query::parse("SELECT 1 / 0 FROM BlobStorage").unwrap();
    assert_eq!(
        query
            .project(&csv(&[]), &Scope { headers: None })
            .unwrap_err()
            .name,
        "DivisionByZero"
    );
}
