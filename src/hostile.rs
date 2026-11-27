//! Tooling for tests that feed hostile text to the parsers of untrusted wire input.
//!
//! A parser of request text must answer any input with a value or an error: never panic,
//! recurse until the stack overflows, or take time that grows faster than the input. These
//! helpers build the inputs; each parser's tests decide what a correct answer is.

/// Fragments that break parsers: quotes, brackets, separators, escapes, numbers at the edge
/// of their type, control and non-ASCII characters.
const NASTY: &[&str] = &[
    "'",
    "\"",
    "''",
    "(",
    ")",
    "[",
    "]",
    "<",
    ">",
    "</",
    "<!--",
    "-->",
    "<![CDATA[",
    "]]>",
    "<?",
    "?>",
    "&",
    "&amp;",
    "&#x110000;",
    "&#0;",
    "&nope;",
    ";",
    ":",
    ",",
    ".",
    "-",
    "+",
    "=",
    "%",
    "%ff",
    "%00",
    "\\",
    "/",
    "*",
    "@",
    "$",
    "\0",
    "\r\n",
    "\n\n",
    "\t",
    " ",
    "\u{e9}",
    "\u{202e}",
    "\u{1f600}",
    "\u{ffff}",
    "0",
    "00000000000000000000",
    "-1",
    "9223372036854775807",
    "9223372036854775808",
    "-9223372036854775808",
    "18446744073709551615",
    "4294967296",
    "1e999",
    "NaN",
    "--",
    "boundary",
];

/// Variants of `seed`: every prefix, every suffix, each character deleted, and each
/// fragment of [`NASTY`] inserted at each position.
pub(crate) fn variants(seed: &str) -> Vec<String> {
    let starts: Vec<usize> = seed
        .char_indices()
        .map(|(at, _)| at)
        .chain([seed.len()])
        .collect();
    let mut out = vec![String::new(), seed.to_owned()];
    for window in starts.windows(2) {
        let (at, next) = (window[0], window[1]);
        out.push(seed[..at].to_owned());
        out.push(seed[at..].to_owned());
        out.push(format!("{}{}", &seed[..at], &seed[next..]));
    }
    for &at in &starts {
        for fragment in NASTY {
            out.push(format!("{}{fragment}{}", &seed[..at], &seed[at..]));
        }
    }
    out
}

/// Inputs far larger than any limit: `seed` and each fragment repeated until it is `size`
/// bytes long, and `opening` repeated that many times then `closing`, for nesting.
pub(crate) fn oversized(seed: &str, size: usize, opening: &str, closing: &str) -> Vec<String> {
    let repeat = |text: &str| text.repeat(size / text.len().max(1) + 1);
    let mut out = vec![repeat(seed), format!("{}{}", repeat(opening), closing)];
    out.extend(NASTY.iter().map(|fragment| repeat(fragment)));
    out
}

/// Runs `work` on a thread with a 1 MiB stack, half of what a runtime worker has, and
/// returns what it returns. A stack overflow aborts the test process, which is the
/// failure this exists to catch; a panic is re-raised here.
pub(crate) fn on_small_stack<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(work)
        .expect("spawn the test thread")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

/// Feeds every variant and oversized form of each seed to `parse` on a small stack.
/// `nesting` is the text that opens and closes one level in the parser's grammar.
pub(crate) fn sweep(seeds: &[&str], nesting: (&str, &str), parse: impl Fn(&str) + Send + 'static) {
    let seeds: Vec<String> = seeds.iter().map(|seed| (*seed).to_owned()).collect();
    let (opening, closing) = (nesting.0.to_owned(), nesting.1.to_owned());
    on_small_stack(move || {
        for seed in &seeds {
            for text in variants(seed) {
                parse(&text);
            }
            for text in oversized(seed, 256 * 1024, &opening, &closing) {
                parse(&text);
            }
        }
    });
}
