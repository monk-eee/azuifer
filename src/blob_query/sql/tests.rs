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

fn eval(expr: &str) -> Result<Value, SqlError> {
    let query = Query::parse(&format!("SELECT {expr} FROM BlobStorage"))?;
    let mut columns = query.project(&csv(&["5", "abc", ""]), &Scope { headers: None })?;
    Ok(columns.remove(0).1)
}

fn failure(expr: &str) -> &'static str {
    eval(expr).expect_err(expr).name
}

#[test]
fn expressions_follow_sql_arithmetic_text_and_cast_rules() {
    let text = |text: &str| Value::Str(text.to_owned());
    for (expr, expected) in [
        ("2 * 3 + 7 % 4 - 10 / 4", Value::Int(7)),
        ("7 / 2.0", Value::Float(3.5)),
        ("7.5 % 2", Value::Float(1.5)),
        ("1e3", Value::Float(1000.0)),
        ("1.5E-1", Value::Float(0.15)),
        ("-_1", Value::Int(-5)),
        ("- -_1", Value::Int(5)),
        ("+5", Value::Int(5)),
        ("-'abc'", Value::Null),
        ("NULL + 1", Value::Null),
        ("'it''s'", text("it's")),
        ("\"_2\"", text("abc")),
        ("'a' || 1", text("a1")),
        ("'a' || NULL", Value::Null),
        ("CAST('42' AS INT)", Value::Int(42)),
        ("CAST(3.9 AS INTEGER)", Value::Int(3)),
        ("CAST(-3.9 AS INT)", Value::Int(-3)),
        ("CAST(1.0e3 AS BIGINT)", Value::Int(1000)),
        ("CAST('2.5' AS FLOAT)", Value::Float(2.5)),
        ("CAST(5 AS STRING)", text("5")),
        ("CAST('TRUE' AS BOOL)", Value::Bool(true)),
        ("CAST(TRUE AS INT)", Value::Int(1)),
        ("CAST(NULL AS INT)", Value::Null),
        ("COALESCE(NULL, NULL, 'x')", text("x")),
        ("COALESCE(NULL)", Value::Null),
        ("NULLIF('a', 'a')", Value::Null),
        ("NULLIF('a', 'b')", text("a")),
        ("LOWER('AbC')", text("abc")),
        ("UPPER(NULL)", Value::Null),
        ("TRIM('  x ')", text("x")),
        ("CHARACTER_LENGTH('héllo')", Value::Int(5)),
        ("SUBSTRING('hello', 2)", text("ello")),
        ("SUBSTRING('hello', 2, 3)", text("ell")),
        ("SUBSTRING('hello', 9)", text("")),
        (
            "SUBSTRING('abc', CAST('-9223372036854775808' AS INT))",
            text("abc"),
        ),
    ] {
        assert_eq!(eval(expr), Ok(expected), "{expr}");
    }
}

#[test]
fn comparisons_and_predicates_keep_three_valued_logic() {
    let null = Value::Null;
    let yes = Value::Bool(true);
    let no = Value::Bool(false);
    for (expr, expected) in [
        ("1 < 2.5", &yes),
        ("'b' > 'a'", &yes),
        // Two text values compare as text, a number against text compares numerically
        // when the text is a number and as text when it is not.
        ("'10' < '9'", &yes),
        ("10 < 9", &no),
        ("_1 = 5", &yes),
        ("_2 = 5", &no),
        ("TRUE = TRUE", &yes),
        ("NULL = NULL", &null),
        ("1 <> 1", &no),
        ("1 != 2", &yes),
        ("1 <= 1 AND 1 >= 1", &yes),
        ("1 IN (2, NULL)", &null),
        ("1 IN (1, NULL)", &yes),
        ("1 NOT IN (2, 3)", &yes),
        ("1 NOT IN (1, NULL)", &no),
        ("NULL IN (1)", &null),
        ("5 BETWEEN 1 AND 10", &yes),
        ("5 NOT BETWEEN 1 AND 3", &yes),
        ("NULL BETWEEN 1 AND 2", &null),
        ("'abc' LIKE 'a%c'", &yes),
        ("'' LIKE '%'", &yes),
        ("'abc' LIKE 'a_'", &no),
        ("'ab' LIKE 'abc'", &no),
        ("'aXbXc' LIKE '%X%X%'", &yes),
        ("'abc' LIKE NULL", &null),
        ("'ab' NOT LIKE 'a'", &yes),
        ("NULL AND FALSE", &no),
        ("NULL AND TRUE", &null),
        ("NULL OR TRUE", &yes),
        ("NULL OR FALSE", &null),
        ("NOT NULL", &null),
        ("NOT 1 = 2", &yes),
        ("NULL IS NULL", &yes),
        ("1 IS NOT NULL", &yes),
    ] {
        assert_eq!(eval(expr).as_ref(), Ok(expected), "{expr}");
    }
}

#[test]
fn runtime_failures_are_named_and_never_panic() {
    let min = "CAST('-9223372036854775808' AS INT)";
    for (expr, name) in [
        ("'a' + 1", "TypeMismatch"),
        ("9223372036854775807 + 1", "Overflow"),
        ("0 - 9223372036854775807 - 2", "Overflow"),
        ("9223372036854775807 * 2", "Overflow"),
        ("7 % 0", "DivisionByZero"),
        ("CAST('x' AS FLOAT)", "InvalidTypeConversion"),
        ("CAST(1 AS BOOL)", "InvalidTypeConversion"),
        ("SUBSTRING('hello', 'x')", "TypeMismatch"),
        ("SUBSTRING('hello', 1, 1.5)", "TypeMismatch"),
        (&format!("-{min}"), "Overflow"),
        (&format!("{min} / -1"), "Overflow"),
    ] {
        assert_eq!(failure(expr), name, "{expr}");
    }
}

#[test]
fn rows_resolve_columns_case_insensitively_and_name_their_output() {
    let json = Row::Json(serde_json::json!({"Name": "x", "tags": ["a"], "n": null}));
    let scope = Scope { headers: None };
    let run = |sql: &str, row: &Row, scope: &Scope<'_>| {
        Query::parse(sql).unwrap().project(row, scope).unwrap()
    };
    let out = run(
        "SELECT name, tags[0], tags[5], name.deep, n, BlobStorage.name FROM BlobStorage",
        &json,
        &scope,
    );
    let names: Vec<&str> = out.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["name", "_2", "_3", "deep", "n", "name"]);
    let values: Vec<&Value> = out.iter().map(|(_, value)| value).collect();
    assert_eq!(values[0], &Value::Str("x".into()));
    assert_eq!(values[1], &Value::Str("a".into()));
    assert_eq!(&values[2..4], [&Value::Null, &Value::Null]);

    let star = run("SELECT * FROM BlobStorage", &json, &scope);
    assert_eq!(star.len(), 3);
    let scalar = run(
        "SELECT * FROM BlobStorage",
        &Row::Json(serde_json::json!(7)),
        &scope,
    );
    assert_eq!(scalar, [("_1".to_owned(), Value::Int(7))]);

    let headers = ["a".to_owned(), String::new()];
    let with_headers = Scope {
        headers: Some(&headers),
    };
    let star = run(
        "SELECT * FROM BlobStorage",
        &csv(&["1", "2", "3"]),
        &with_headers,
    );
    let names: Vec<&str> = star.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        names,
        ["a", "_2", "_3"],
        "an empty or missing header falls back to its position"
    );
    let named = run(
        "SELECT A, _0, _9, a.b, 1 + 1, UPPER(a) FROM BlobStorage",
        &csv(&["x", "y"]),
        &with_headers,
    );
    let values: Vec<&Value> = named.iter().map(|(_, value)| value).collect();
    assert_eq!(values[0], &Value::Str("x".into()));
    assert_eq!(&values[1..4], [&Value::Null, &Value::Null, &Value::Null]);
    assert_eq!(values[4], &Value::Int(2));
    assert_eq!(named[4].0, "_5");
}

#[test]
fn aggregates_skip_nulls_and_report_overflow_and_type_errors() {
    let run = |sql: &str, rows: &[Row]| -> Result<Vec<Value>, SqlError> {
        let query = Query::parse(sql).unwrap();
        let scope = Scope { headers: None };
        let mut accumulators = query.accumulators();
        for row in rows {
            query.accumulate(&mut accumulators, row, &scope)?;
        }
        Ok(accumulators.into_iter().map(Accumulator::finish).collect())
    };
    let json = |value: serde_json::Value| Row::Json(serde_json::json!({ "a": value }));
    let all = "SELECT COUNT(*), COUNT(a), SUM(a), AVG(a), MIN(a), MAX(a) FROM BlobStorage";

    assert_eq!(
        run(all, &[]),
        Ok(vec![
            Value::Int(0),
            Value::Int(0),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null
        ])
    );
    let mixed = [
        json(1.into()),
        json(serde_json::Value::Null),
        json(2.5.into()),
    ];
    assert_eq!(
        run(all, &mixed),
        Ok(vec![
            Value::Int(3),
            Value::Int(2),
            Value::Float(3.5),
            Value::Float(1.75),
            Value::Int(1),
            Value::Float(2.5),
        ])
    );
    let big = [json(i64::MAX.into()), json(1.into())];
    assert_eq!(
        run("SELECT SUM(a) FROM BlobStorage", &big),
        Ok(vec![Value::Float(i64::MAX as f64 + 1.0)]),
        "an integer sum that would overflow carries on as a float"
    );
    let words = [json("x".into())];
    assert_eq!(
        run("SELECT SUM(a) FROM BlobStorage", &words)
            .unwrap_err()
            .name,
        "TypeMismatch"
    );
    assert_eq!(
        run("SELECT AVG(a + 'q') FROM BlobStorage", &mixed)
            .unwrap_err()
            .name,
        "TypeMismatch"
    );
}

#[test]
fn malformed_sql_is_a_parse_error() {
    for sql in [
        "",
        "SELECT",
        "SELECT # FROM BlobStorage",
        "SELECT 'open FROM BlobStorage",
        "SELECT \"open FROM BlobStorage",
        "SELECT 1.2.3 FROM BlobStorage",
        "SELECT ) FROM BlobStorage",
        "SELECT (1 FROM BlobStorage",
        "SELECT select FROM BlobStorage",
        "SELECT _1 AS FROM BlobStorage",
        "SELECT * FROM BlobStorage AS",
        "SELECT * FROM BlobStorage LIMIT",
        "SELECT * FROM BlobStorage LIMIT 1.5",
        "SELECT * FROM BlobStorage LIMIT -1",
        "SELECT * FROM BlobStorage LIMIT 99999999999999999999",
        "SELECT * FROM BlobStorage s extra",
        "SELECT * FROM BlobStorage WHERE NOT",
        "SELECT * FROM BlobStorage WHERE _1 IN ()",
        "SELECT * FROM BlobStorage WHERE _1 IN (1",
        "SELECT * FROM BlobStorage WHERE _1 BETWEEN 1 2",
        "SELECT * FROM BlobStorage WHERE _1 IS 3",
        "SELECT * FROM BlobStorage WHERE _1 LIKE",
        "SELECT a[x] FROM BlobStorage",
        "SELECT a[1 FROM BlobStorage",
        "SELECT a[99999999999999999999999] FROM BlobStorage",
        "SELECT a. FROM BlobStorage",
        "SELECT CAST(1 INT) FROM BlobStorage",
        "SELECT CAST(1 AS blob) FROM BlobStorage",
        "SELECT COUNT(COUNT(*)) FROM BlobStorage",
        "SELECT SUM(*) FROM BlobStorage",
        "SELECT LOWER(1, 2) FROM BlobStorage",
        "SELECT SUBSTRING('a') FROM BlobStorage",
        "SELECT NULLIF(1) FROM BlobStorage",
        "SELECT COALESCE() FROM BlobStorage",
        "SELECT COUNT(*) + 1 FROM BlobStorage",
    ] {
        assert_eq!(Query::parse(sql).unwrap_err().name, "ParseError", "{sql:?}");
    }
    let limited = Query::parse("select _1 from blobstorage limit 0;").unwrap();
    assert_eq!(limited.limit, Some(0), "a trailing semicolon is ignored");
}

#[test]
fn hostile_text_never_panics() {
    let rich = "SELECT s.a[0] AS x, CAST(_1 AS FLOAT) + 1.5e3 * -2, SUBSTRING(UPPER(_2), 1, 3) || 'it''s' \
                FROM BlobStorage s WHERE NOT (_1 BETWEEN 1 AND 9 OR _2 NOT LIKE 'a%' AND _3 IN (1, 2, NULL)) \
                AND COALESCE(NULLIF(_1, ''), 'z') IS NOT NULL LIMIT 7";
    let rows = [
        csv(&["5", "abc", ""]),
        csv(&[]),
        Row::Json(serde_json::json!({"a": [1], "_1": "q"})),
    ];
    let mut inputs: Vec<String> = rich
        .char_indices()
        .flat_map(|(at, _)| [rich[..at].to_owned(), rich[at..].to_owned()])
        .collect();
    inputs.extend(
        [
            "\0",
            "SELECT \u{202e}x FROM BlobStorage",
            "SELECT 'é\u{0}' FROM BlobStorage WHERE '\u{1f600}' LIKE '%_'",
            "SELECT 1e999, -1e999, 1e-999 FROM BlobStorage",
            "SELECT 9999999999999999999999999999 FROM BlobStorage",
            "SELECT a[18446744073709551615] FROM BlobStorage",
            "SELECT CAST('nan' AS FLOAT), CAST('inf' AS INT), CAST('1e999' AS INT) FROM BlobStorage",
            "SELECT SUBSTRING('abc', 1, 9223372036854775807), SUBSTRING('abc', 9223372036854775807) FROM BlobStorage",
            "SELECT '%%%%%%%%%%%%%%%%%%%%' LIKE '%%%%%%%%%%%%%%%%%%%%a' FROM BlobStorage",
        ]
        .map(str::to_owned),
    );
    for sql in &inputs {
        if let Ok(query) = Query::parse(sql) {
            for row in &rows {
                let scope = Scope { headers: None };
                let _ = query.matches(row, &scope);
                let _ = query.project(row, &scope);
            }
        }
    }
}

#[test]
fn deeply_nested_or_chained_expressions_are_refused_before_they_exhaust_the_stack() {
    // Each shape, with a depth a written query could reach and one that is hostile.
    type Shape = (&'static str, fn(usize) -> String, usize);
    let shapes: [Shape; 9] = [
        (
            "parentheses",
            |n| {
                format!(
                    "SELECT {}1{} FROM BlobStorage",
                    "(".repeat(n),
                    ")".repeat(n)
                )
            },
            60,
        ),
        (
            "functions",
            |n| {
                format!(
                    "SELECT {}1{} FROM BlobStorage",
                    "UPPER(".repeat(n),
                    ")".repeat(n)
                )
            },
            20,
        ),
        (
            "negation",
            |n| format!("SELECT {}_1 FROM BlobStorage", "-".repeat(n)),
            60,
        ),
        (
            "NOT",
            |n| format!("SELECT * FROM BlobStorage WHERE {}_1 = 1", "NOT ".repeat(n)),
            60,
        ),
        (
            "sums",
            |n| format!("SELECT 1{} FROM BlobStorage", "+1".repeat(n)),
            100,
        ),
        (
            "products",
            |n| format!("SELECT 1{} FROM BlobStorage", "*1".repeat(n)),
            100,
        ),
        (
            "concatenations",
            |n| format!("SELECT 'a'{} FROM BlobStorage", " || 'a'".repeat(n)),
            100,
        ),
        (
            "OR chain",
            |n| {
                format!(
                    "SELECT * FROM BlobStorage WHERE _1 = 1{}",
                    " OR _1 = 1".repeat(n)
                )
            },
            100,
        ),
        (
            "AND chain",
            |n| {
                format!(
                    "SELECT * FROM BlobStorage WHERE _1 = 1{}",
                    " AND _1 = 1".repeat(n)
                )
            },
            100,
        ),
    ];
    // The query is parsed, run and dropped on a thread with half the stack of a runtime worker.
    let on_small_stack = |sql: String| {
        std::thread::Builder::new()
            .stack_size(1 << 20)
            .spawn(move || {
                Query::parse(&sql)
                    .map(|query| {
                        let scope = Scope { headers: None };
                        let row = csv(&["1"]);
                        let _ = query.matches(&row, &scope);
                        let _ = query.project(&row, &scope);
                    })
                    .map_err(|error| error.name)
            })
            .unwrap()
            .join()
            .expect("no stack overflow")
    };
    for (shape, build, fine) in shapes {
        assert_eq!(on_small_stack(build(fine)), Ok(()), "{shape} {fine} deep");
        assert_eq!(
            on_small_stack(build(100_000)),
            Err("ParseError"),
            "{shape} 100000 deep"
        );
    }
}
