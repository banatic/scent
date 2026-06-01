//! A small, honest subset of the Sigma rule engine.
//!
//! It compiles a Sigma YAML rule into a `CompiledRule` (selections + a parsed
//! `condition`) and evaluates it against a `sigma_fields`-produced field map.
//! The design rule is **fail closed on load, never at eval**: anything the engine
//! can't faithfully represent — an unsupported value modifier, a condition syntax
//! it doesn't parse, a field scent never produces — causes the rule to be
//! *skipped at load time* and counted in the [`LoadReport`], not silently
//! mis-evaluated. The goal is a precisely-known subset, not maximal coverage.
//!
//! Supported value modifiers: `contains startswith endswith all re cidr windash
//! base64 base64offset` (+ regex flags `i m s`). Supported condition grammar:
//! selection names, `and`/`or`/`not`, parentheses, and `1 of` / `all of` over
//! `them` or a `name*` prefix.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use regex::Regex;
use serde::Serialize;

use crate::model::Severity;
use crate::sigma_fields::SigmaCategory;

/// Sigma severity level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Level {
    fn parse(s: &str) -> Level {
        match s.trim().to_lowercase().as_str() {
            "critical" => Level::Critical,
            "high" => Level::High,
            "medium" => Level::Medium,
            "low" => Level::Low,
            _ => Level::Informational,
        }
    }

    /// Map a Sigma level to a triage severity.
    pub fn severity(self) -> Severity {
        match self {
            Level::Critical => Severity::Critical,
            Level::High => Severity::High,
            Level::Medium => Severity::Med,
            Level::Low => Severity::Low,
            Level::Informational => Severity::Info,
        }
    }
}

/// A rule compiled to an evaluable form. Shared read-only via `Arc` at runtime,
/// so it deliberately isn't `Clone` (its `Regex`/`Cond` internals needn't be).
pub struct CompiledRule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub level: Level,
    pub status: String,
    /// ATT&CK technique IDs extracted from tags (e.g. "T1059.001").
    pub tags: Vec<String>,
    pub category: SigmaCategory,
    selections: BTreeMap<String, Selection>,
    cond: Cond,
}

impl CompiledRule {
    /// Evaluate against one event's Sigma field map.
    pub fn eval(&self, fields: &BTreeMap<String, String>) -> bool {
        self.cond.eval(&self.selections, fields)
    }
}

/// Why a rule was rejected at load time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reject {
    /// Uses a modifier / condition / category the engine can't represent.
    Unsupported,
    /// References a field scent never produces for its category.
    MissingFields,
}

/// Outcome counts from loading a directory of rules.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct LoadReport {
    pub loaded: usize,
    pub skipped_unsupported: usize,
    pub skipped_missing_fields: usize,
}

// ---- Value matching --------------------------------------------------------

/// One precompiled value test (already lowercased where literal).
enum ValueMatch {
    Equals(String),
    Contains(String),
    StartsWith(String),
    EndsWith(String),
    Regex(Regex),
    Cidr { net: u32, mask: u32 },
    /// OR over alternatives (windash / base64 expansions).
    Any(Vec<ValueMatch>),
}

impl ValueMatch {
    /// `hay` is the raw field value, `lc` its lowercase (literal matchers use `lc`).
    fn matches(&self, hay: &str, lc: &str) -> bool {
        match self {
            ValueMatch::Equals(v) => lc == v,
            ValueMatch::Contains(v) => lc.contains(v.as_str()),
            ValueMatch::StartsWith(v) => lc.starts_with(v.as_str()),
            ValueMatch::EndsWith(v) => lc.ends_with(v.as_str()),
            ValueMatch::Regex(re) => re.is_match(hay),
            ValueMatch::Cidr { net, mask } => match parse_ipv4(hay) {
                Some(ip) => (ip & mask) == *net,
                None => false,
            },
            ValueMatch::Any(vs) => vs.iter().any(|v| v.matches(hay, lc)),
        }
    }
}

/// Base comparison op selected by contains/startswith/endswith modifiers.
#[derive(Clone, Copy)]
enum Base {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
}

// ---- Selections ------------------------------------------------------------

struct FieldMatcher {
    field: String,
    values: Vec<ValueMatch>,
    /// `|all`: every value must match (else any).
    all: bool,
    /// Rule wrote `field: null` — match when the field is absent/empty.
    match_null: bool,
}

impl FieldMatcher {
    fn matches(&self, fields: &BTreeMap<String, String>) -> bool {
        let Some(hay) = fields.get(&self.field) else {
            return self.match_null;
        };
        if self.match_null {
            return hay.is_empty();
        }
        let lc = hay.to_lowercase();
        if self.all {
            self.values.iter().all(|v| v.matches(hay, &lc))
        } else {
            self.values.iter().any(|v| v.matches(hay, &lc))
        }
    }
}

enum Selection {
    /// A map: AND across fields.
    Map(Vec<FieldMatcher>),
    /// A list of maps: OR across them (each AND within).
    OrMaps(Vec<Vec<FieldMatcher>>),
    /// Bare-string keyword list: match if ANY field value contains ANY keyword.
    Keywords(Vec<ValueMatch>),
}

impl Selection {
    fn matches(&self, fields: &BTreeMap<String, String>) -> bool {
        match self {
            Selection::Map(fs) => fs.iter().all(|f| f.matches(fields)),
            Selection::OrMaps(maps) => {
                maps.iter().any(|fs| fs.iter().all(|f| f.matches(fields)))
            }
            Selection::Keywords(ks) => fields.values().any(|v| {
                let lc = v.to_lowercase();
                ks.iter().any(|k| k.matches(v, &lc))
            }),
        }
    }

    /// Field names referenced (for the provided-fields gate). Keyword selections
    /// reference no specific field (they search all), so they list none.
    fn fields(&self) -> Vec<&str> {
        match self {
            Selection::Map(fs) => fs.iter().map(|f| f.field.as_str()).collect(),
            Selection::OrMaps(maps) => {
                maps.iter().flatten().map(|f| f.field.as_str()).collect()
            }
            Selection::Keywords(_) => Vec::new(),
        }
    }
}

// ---- Condition AST ---------------------------------------------------------

enum Cond {
    Sel(String),
    And(Box<Cond>, Box<Cond>),
    Or(Box<Cond>, Box<Cond>),
    Not(Box<Cond>),
    /// `1 of <pat>` (OR) / `all of <pat>` (AND).
    Quant { all: bool, pat: Pat },
}

enum Pat {
    Them,
    Prefix(String),
    Name(String),
}

impl Pat {
    fn selected<'a>(&self, sels: &'a BTreeMap<String, Selection>) -> Vec<&'a Selection> {
        sels.iter()
            .filter(|(name, _)| match self {
                Pat::Them => true,
                Pat::Prefix(p) => name.starts_with(p),
                Pat::Name(n) => name.as_str() == n,
            })
            .map(|(_, s)| s)
            .collect()
    }
}

impl Cond {
    fn eval(&self, sels: &BTreeMap<String, Selection>, f: &BTreeMap<String, String>) -> bool {
        match self {
            Cond::Sel(name) => sels.get(name).map(|s| s.matches(f)).unwrap_or(false),
            Cond::And(a, b) => a.eval(sels, f) && b.eval(sels, f),
            Cond::Or(a, b) => a.eval(sels, f) || b.eval(sels, f),
            Cond::Not(a) => !a.eval(sels, f),
            Cond::Quant { all, pat } => {
                let chosen = pat.selected(sels);
                if chosen.is_empty() {
                    return false; // no vacuous-truth false positives
                }
                if *all {
                    chosen.iter().all(|s| s.matches(f))
                } else {
                    chosen.iter().any(|s| s.matches(f))
                }
            }
        }
    }

    /// Selection names referenced by a `Sel` node (for validation).
    fn referenced_names<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Cond::Sel(n) => out.push(n.as_str()),
            Cond::And(a, b) | Cond::Or(a, b) => {
                a.referenced_names(out);
                b.referenced_names(out);
            }
            Cond::Not(a) => a.referenced_names(out),
            Cond::Quant { .. } => {}
        }
    }
}

// ---- Loading ---------------------------------------------------------------

/// Load every `*.yml`/`*.yaml` rule under `dir` (recursively). Returns the
/// compiled rules plus a breakdown of what was skipped and why.
pub fn load_rules(dir: &Path) -> (Vec<CompiledRule>, LoadReport) {
    let mut rules = Vec::new();
    let mut report = LoadReport::default();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "yml" && ext != "yaml" {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&p) else { continue };
            match compile(&text) {
                Ok(rule) => {
                    report.loaded += 1;
                    rules.push(rule);
                }
                Err(Reject::Unsupported) => report.skipped_unsupported += 1,
                Err(Reject::MissingFields) => report.skipped_missing_fields += 1,
            }
        }
    }
    (rules, report)
}

/// Compile a single rule from YAML text. Public for tests.
pub fn compile_str(text: &str) -> Result<CompiledRule, ()> {
    compile(text).map_err(|_| ())
}

fn compile(text: &str) -> Result<CompiledRule, Reject> {
    // Take the first YAML document (correlation rules append extra docs).
    let doc: serde_yaml::Value = serde_yaml::from_str(text).map_err(|_| Reject::Unsupported)?;
    let map = doc.as_mapping().ok_or(Reject::Unsupported)?;

    let get_str = |k: &str| -> Option<String> {
        map.get(serde_yaml::Value::from(k))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };

    // Correlation rules have `correlation`, not `detection`.
    if map.contains_key(serde_yaml::Value::from("correlation")) {
        return Err(Reject::Unsupported);
    }

    let category_str = map
        .get(serde_yaml::Value::from("logsource"))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::from("category")))
        .and_then(|v| v.as_str())
        .ok_or(Reject::Unsupported)?;
    let category = SigmaCategory::from_str(category_str).ok_or(Reject::Unsupported)?;

    let detection = map
        .get(serde_yaml::Value::from("detection"))
        .and_then(|v| v.as_mapping())
        .ok_or(Reject::Unsupported)?;

    let mut selections: BTreeMap<String, Selection> = BTreeMap::new();
    let mut condition: Option<String> = None;
    for (k, v) in detection {
        let Some(name) = k.as_str() else { continue };
        if name == "condition" {
            // A list condition means an implicit OR of multiple conditions; not
            // supported (rare). A single string is the norm.
            condition = Some(v.as_str().ok_or(Reject::Unsupported)?.to_string());
            continue;
        }
        if name == "timeframe" {
            return Err(Reject::Unsupported); // aggregation, out of scope
        }
        selections.insert(name.to_string(), compile_selection(v)?);
    }
    let condition = condition.ok_or(Reject::Unsupported)?;
    let cond = parse_condition(&condition)?;

    // Every selection referenced by the condition must exist.
    let mut refs = Vec::new();
    cond.referenced_names(&mut refs);
    if refs.iter().any(|n| !selections.contains_key(*n)) {
        return Err(Reject::Unsupported);
    }

    // Every field referenced must be one scent can supply for this category.
    let provided = category.provided_fields();
    for sel in selections.values() {
        for field in sel.fields() {
            if !provided.contains(&field) {
                return Err(Reject::MissingFields);
            }
        }
    }

    let tags = extract_techniques(map.get(serde_yaml::Value::from("tags")));

    Ok(CompiledRule {
        id: get_str("id").unwrap_or_default(),
        title: get_str("title").unwrap_or_else(|| "(untitled)".into()),
        description: get_str("description").unwrap_or_default(),
        level: get_str("level").map(|l| Level::parse(&l)).unwrap_or(Level::Informational),
        status: get_str("status").unwrap_or_default(),
        tags,
        category,
        selections,
        cond,
    })
}

/// Rules indexed by Sigma category, so per-event evaluation only touches the
/// rules whose logsource matches the event.
pub struct RuleSet {
    by_cat: HashMap<SigmaCategory, Vec<CompiledRule>>,
    total: usize,
}

impl RuleSet {
    pub fn new(rules: Vec<CompiledRule>) -> RuleSet {
        let total = rules.len();
        let mut by_cat: HashMap<SigmaCategory, Vec<CompiledRule>> = HashMap::new();
        for r in rules {
            by_cat.entry(r.category).or_default().push(r);
        }
        RuleSet { by_cat, total }
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    pub fn len(&self) -> usize {
        self.total
    }

    /// Rules whose logsource category matches `cat` (empty slice if none).
    pub fn for_category(&self, cat: SigmaCategory) -> &[CompiledRule] {
        self.by_cat.get(&cat).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

/// Resolve the bundled ruleset directory and load it. Tries `<exe-dir>/rules`
/// (shipped) then the dev tree, returning an empty set if neither exists — scent
/// runs fine with no Sigma rules (heuristics + raw telemetry still work).
pub fn load_default_ruleset() -> RuleSet {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("rules").join("stable_medium_plus"));
        }
    }
    candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules/stable_medium_plus"));

    for dir in candidates {
        if dir.is_dir() {
            let (rules, report) = load_rules(&dir);
            eprintln!(
                "[sigma] loaded {} rules from {} ({:?})",
                rules.len(),
                dir.display(),
                report
            );
            return RuleSet::new(rules);
        }
    }
    eprintln!("[sigma] no ruleset directory found; Sigma detection disabled");
    RuleSet::new(Vec::new())
}

fn extract_techniques(tags: Option<&serde_yaml::Value>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(seq) = tags.and_then(|t| t.as_sequence()) {
        for t in seq {
            if let Some(s) = t.as_str() {
                let l = s.to_lowercase();
                if let Some(rest) = l.strip_prefix("attack.t") {
                    // attack.t1059.001 -> T1059.001 (technique IDs only).
                    if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                        out.push(format!("T{}", rest.to_uppercase()));
                    }
                }
            }
        }
    }
    out
}

// ---- Selection compilation -------------------------------------------------

fn compile_selection(v: &serde_yaml::Value) -> Result<Selection, Reject> {
    match v {
        serde_yaml::Value::Mapping(m) => Ok(Selection::Map(compile_field_map(m)?)),
        serde_yaml::Value::Sequence(seq) => {
            if seq.iter().all(|i| i.is_mapping()) {
                let mut maps = Vec::new();
                for i in seq {
                    maps.push(compile_field_map(i.as_mapping().unwrap())?);
                }
                Ok(Selection::OrMaps(maps))
            } else if seq.iter().all(|i| i.as_str().is_some() || i.is_number()) {
                // Keyword list: each searched with `contains` across all fields.
                let mut ks = Vec::new();
                for i in seq {
                    let s = scalar_to_string(i).ok_or(Reject::Unsupported)?;
                    ks.push(ValueMatch::Contains(s.to_lowercase()));
                }
                Ok(Selection::Keywords(ks))
            } else {
                Err(Reject::Unsupported)
            }
        }
        _ => Err(Reject::Unsupported),
    }
}

fn compile_field_map(m: &serde_yaml::Mapping) -> Result<Vec<FieldMatcher>, Reject> {
    let mut out = Vec::new();
    for (k, v) in m {
        let key = k.as_str().ok_or(Reject::Unsupported)?;
        out.push(compile_field(key, v)?);
    }
    Ok(out)
}

fn compile_field(key: &str, value: &serde_yaml::Value) -> Result<FieldMatcher, Reject> {
    let mut parts = key.split('|');
    let field = parts.next().unwrap_or("").to_string();

    let mut base = Base::Equals;
    let mut transforms: Vec<Transform> = Vec::new();
    let mut is_re = false;
    let mut is_cidr = false;
    let mut all = false;
    let mut re_flags = String::new();
    for m in parts {
        match m {
            "contains" => base = Base::Contains,
            "startswith" => base = Base::StartsWith,
            "endswith" => base = Base::EndsWith,
            "all" => all = true,
            "re" => is_re = true,
            "cidr" => is_cidr = true,
            "windash" => transforms.push(Transform::Windash),
            "base64" => transforms.push(Transform::Base64),
            "base64offset" => transforms.push(Transform::Base64Offset),
            "i" | "m" | "s" => re_flags.push_str(m),
            _ => return Err(Reject::Unsupported),
        }
    }

    // Collect raw values (scalar or sequence), tracking a `null` (match-absent).
    let mut raw: Vec<String> = Vec::new();
    let mut match_null = false;
    match value {
        serde_yaml::Value::Null => match_null = true,
        serde_yaml::Value::Sequence(seq) => {
            for i in seq {
                if i.is_null() {
                    match_null = true;
                } else {
                    raw.push(scalar_to_string(i).ok_or(Reject::Unsupported)?);
                }
            }
        }
        other => raw.push(scalar_to_string(other).ok_or(Reject::Unsupported)?),
    }

    let mut values = Vec::new();
    for r in &raw {
        values.push(build_value(r, base, &transforms, is_re, is_cidr, &re_flags)?);
    }

    Ok(FieldMatcher {
        field,
        values,
        all,
        match_null,
    })
}

#[derive(Clone, Copy)]
enum Transform {
    Windash,
    Base64,
    Base64Offset,
}

fn build_value(
    raw: &str,
    base: Base,
    transforms: &[Transform],
    is_re: bool,
    is_cidr: bool,
    re_flags: &str,
) -> Result<ValueMatch, Reject> {
    if is_re {
        // Spec: default case-insensitive (the `i` flag is then a no-op).
        let re = regex::RegexBuilder::new(raw)
            .case_insensitive(true)
            .multi_line(re_flags.contains('m'))
            .dot_matches_new_line(re_flags.contains('s'))
            .build()
            .map_err(|_| Reject::Unsupported)?;
        return Ok(ValueMatch::Regex(re));
    }
    if is_cidr {
        return parse_cidr(raw).map(|(net, mask)| ValueMatch::Cidr { net, mask }).ok_or(Reject::Unsupported);
    }

    // Expand transforms into literal alternatives, then apply the base op.
    let mut alts = vec![raw.to_string()];
    for t in transforms {
        let mut next = Vec::new();
        for a in &alts {
            match t {
                Transform::Windash => next.extend(windash_variants(a)),
                Transform::Base64 => next.push(B64.encode(a.as_bytes())),
                Transform::Base64Offset => next.extend(base64offset_variants(a)),
            }
        }
        alts = next;
    }

    let mk = |s: &str| -> ValueMatch {
        let lc = s.to_lowercase();
        match base {
            Base::Equals => ValueMatch::Equals(lc),
            Base::Contains => ValueMatch::Contains(lc),
            Base::StartsWith => ValueMatch::StartsWith(lc),
            Base::EndsWith => ValueMatch::EndsWith(lc),
        }
    };
    if alts.len() == 1 {
        Ok(mk(&alts[0]))
    } else {
        Ok(ValueMatch::Any(alts.iter().map(|a| mk(a)).collect()))
    }
}

fn scalar_to_string(v: &serde_yaml::Value) -> Option<String> {
    match v {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Sigma `windash`: the dash that introduces a switch can be any of `- / – — ―`.
fn windash_variants(s: &str) -> Vec<String> {
    const DASHES: &[char] = &['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];
    let mut out = vec![s.to_string()];
    for &d in &DASHES[1..] {
        out.push(s.replace('-', &d.to_string()));
    }
    out
}

/// Sigma `base64offset`: the value may sit at one of three byte alignments inside
/// a longer base64 stream, so emit the three encodings with the partial leading/
/// trailing base64 chars trimmed.
fn base64offset_variants(s: &str) -> Vec<String> {
    const START: [usize; 3] = [0, 2, 3];
    const END_TRIM: [usize; 3] = [0, 3, 2];
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    for i in 0..3 {
        let mut buf = vec![b' '; i];
        buf.extend_from_slice(bytes);
        let enc = B64.encode(&buf);
        let end = enc.len().saturating_sub(END_TRIM[i]);
        if START[i] <= end {
            out.push(enc[START[i]..end].to_string());
        }
    }
    out
}

// ---- IPv4 / CIDR -----------------------------------------------------------

fn parse_ipv4(s: &str) -> Option<u32> {
    let mut octs = [0u32; 4];
    let mut n = 0;
    for part in s.trim().split('.') {
        if n >= 4 {
            return None;
        }
        let o: u32 = part.parse().ok()?;
        if o > 255 {
            return None;
        }
        octs[n] = o;
        n += 1;
    }
    if n != 4 {
        return None;
    }
    Some((octs[0] << 24) | (octs[1] << 16) | (octs[2] << 8) | octs[3])
}

fn parse_cidr(s: &str) -> Option<(u32, u32)> {
    let (ip, bits) = s.split_once('/')?;
    let addr = parse_ipv4(ip)?;
    let prefix: u32 = bits.trim().parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    Some((addr & mask, mask))
}

// ---- Condition parser ------------------------------------------------------

fn parse_condition(s: &str) -> Result<Cond, Reject> {
    let spaced = s.replace('(', " ( ").replace(')', " ) ");
    let tokens: Vec<String> = spaced.split_whitespace().map(|t| t.to_string()).collect();
    if tokens.is_empty() {
        return Err(Reject::Unsupported);
    }
    let mut p = CondParser { tokens: &tokens, pos: 0 };
    let c = p.parse_or()?;
    if p.pos != p.tokens.len() {
        return Err(Reject::Unsupported);
    }
    Ok(c)
}

struct CondParser<'a> {
    tokens: &'a [String],
    pos: usize,
}

impl<'a> CondParser<'a> {
    fn peek(&self) -> Option<&str> {
        self.tokens.get(self.pos).map(|s| s.as_str())
    }
    fn eat(&mut self) -> Option<&str> {
        let t = self.tokens.get(self.pos).map(|s| s.as_str());
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn eat_kw(&mut self, kw: &str) -> bool {
        if self.peek().map(|t| t.eq_ignore_ascii_case(kw)).unwrap_or(false) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse_or(&mut self) -> Result<Cond, Reject> {
        let mut left = self.parse_and()?;
        while self.eat_kw("or") {
            let right = self.parse_and()?;
            left = Cond::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Cond, Reject> {
        let mut left = self.parse_not()?;
        while self.eat_kw("and") {
            let right = self.parse_not()?;
            left = Cond::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Cond, Reject> {
        if self.eat_kw("not") {
            return Ok(Cond::Not(Box::new(self.parse_not()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Cond, Reject> {
        match self.peek() {
            Some("(") => {
                self.eat();
                let c = self.parse_or()?;
                if !self.eat_kw(")") {
                    return Err(Reject::Unsupported);
                }
                Ok(c)
            }
            Some(t) if t.eq_ignore_ascii_case("1") || t.eq_ignore_ascii_case("all") => {
                let all = t.eq_ignore_ascii_case("all");
                self.eat();
                if !self.eat_kw("of") {
                    // bare `all`/`1` isn't a valid primary
                    return Err(Reject::Unsupported);
                }
                let pat = match self.eat() {
                    Some(p) if p.eq_ignore_ascii_case("them") => Pat::Them,
                    Some(p) if p.ends_with('*') => Pat::Prefix(p[..p.len() - 1].to_string()),
                    Some(p) => Pat::Name(p.to_string()),
                    None => return Err(Reject::Unsupported),
                };
                Ok(Cond::Quant { all, pat })
            }
            Some(t)
                if t.eq_ignore_ascii_case("and")
                    || t.eq_ignore_ascii_case("or")
                    || t.eq_ignore_ascii_case("of")
                    || t == ")" =>
            {
                Err(Reject::Unsupported)
            }
            Some(_) => {
                let name = self.eat().unwrap().to_string();
                Ok(Cond::Sel(name))
            }
            None => Err(Reject::Unsupported),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn encoded_powershell_matches_and_misses() {
        let yaml = r#"
title: Encoded PowerShell Command Line
id: 11111111-1111-1111-1111-111111111111
status: test
level: high
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_enc:
        CommandLine|contains:
            - ' -enc '
            - ' -EncodedCommand '
    condition: selection_img and selection_enc
"#;
        let rule = compile_str(yaml).expect("compile");
        assert_eq!(rule.level, Level::High);
        assert_eq!(rule.tags, vec!["T1059.001".to_string()]);
        // Case-insensitive + list OR + endswith.
        assert!(rule.eval(&fields(&[
            ("Image", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.EXE"),
            ("CommandLine", "powershell.exe -ENC SQBFAFgA"),
        ])));
        // Missing the encoded flag → no match.
        assert!(!rule.eval(&fields(&[
            ("Image", "C:\\Windows\\System32\\cmd.exe"),
            ("CommandLine", "powershell.exe -File a.ps1"),
        ])));
    }

    #[test]
    fn office_child_shell_with_filter() {
        let yaml = r#"
title: Office Spawning Shell
id: 22222222-2222-2222-2222-222222222222
status: stable
level: high
tags: [attack.t1059, attack.execution]
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\winword.exe'
            - '\excel.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
    filter:
        CommandLine|contains: '/safe'
    condition: selection and not filter
"#;
        let rule = compile_str(yaml).expect("compile");
        assert!(rule.eval(&fields(&[
            ("ParentImage", "C:\\Program Files\\Microsoft Office\\winword.exe"),
            ("Image", "C:\\Windows\\System32\\cmd.exe"),
            ("CommandLine", "cmd /c whoami"),
        ])));
        // The filter (not) excludes the /safe variant.
        assert!(!rule.eval(&fields(&[
            ("ParentImage", "C:\\Program Files\\Microsoft Office\\winword.exe"),
            ("Image", "C:\\Windows\\System32\\cmd.exe"),
            ("CommandLine", "cmd /c something /safe mode"),
        ])));
        // Non-Office parent → no match.
        assert!(!rule.eval(&fields(&[
            ("ParentImage", "C:\\Windows\\explorer.exe"),
            ("Image", "C:\\Windows\\System32\\cmd.exe"),
            ("CommandLine", "cmd /c whoami"),
        ])));
    }

    #[test]
    fn registry_set_run_key() {
        let yaml = r#"
title: Run Key Persistence
id: 33333333-3333-3333-3333-333333333333
status: stable
level: medium
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\CurrentVersion\Run\'
    condition: selection
"#;
        let rule = compile_str(yaml).expect("compile");
        assert_eq!(rule.category, SigmaCategory::RegistrySet);
        assert!(rule.eval(&fields(&[(
            "TargetObject",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil",
        )])));
        assert!(!rule.eval(&fields(&[(
            "TargetObject",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\X",
        )])));
    }

    #[test]
    fn unsupported_modifier_is_rejected() {
        let yaml = r#"
title: Uses fieldref
id: 44444444-4444-4444-4444-444444444444
logsource:
    category: process_creation
detection:
    selection:
        Image|fieldref: ParentImage
    condition: selection
"#;
        assert!(matches!(compile(yaml), Err(Reject::Unsupported)));
    }

    #[test]
    fn missing_field_is_rejected() {
        let yaml = r#"
title: Uses a field scent never provides
id: 55555555-5555-5555-5555-555555555555
logsource:
    category: process_creation
detection:
    selection:
        Hashes|contains: 'deadbeef'
    condition: selection
"#;
        assert!(matches!(compile(yaml), Err(Reject::MissingFields)));
    }

    #[test]
    fn one_of_them_quantifier() {
        let yaml = r#"
title: Any suspicious flag
id: 66666666-6666-6666-6666-666666666666
logsource:
    category: process_creation
detection:
    sel_a:
        CommandLine|contains: 'mimikatz'
    sel_b:
        CommandLine|contains: 'sekurlsa'
    condition: 1 of sel_*
"#;
        let rule = compile_str(yaml).expect("compile");
        assert!(rule.eval(&fields(&[("CommandLine", "x sekurlsa::logonpasswords")])));
        assert!(!rule.eval(&fields(&[("CommandLine", "notepad.exe")])));
    }

    #[test]
    fn cidr_modifier() {
        let yaml = r#"
title: Internal beacon
id: 77777777-7777-7777-7777-777777777777
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp|cidr: '10.0.0.0/8'
    condition: selection
"#;
        let rule = compile_str(yaml).expect("compile");
        assert!(rule.eval(&fields(&[("DestinationIp", "10.4.5.6")])));
        assert!(!rule.eval(&fields(&[("DestinationIp", "93.184.216.34")])));
    }

    #[test]
    fn curated_ruleset_loads_cleanly() {
        // Cross-check the Python curator against the Rust engine: nearly every
        // curated rule should compile (the curator mirrors this engine's rules).
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules");
        if !base.exists() {
            return; // ruleset not curated in this checkout
        }
        let (rules, report) = load_rules(&base);
        println!("curated load report: {report:?}, compiled={}", rules.len());
        assert!(report.loaded > 0, "expected curated rules to load");
        let total = report.loaded + report.skipped_unsupported + report.skipped_missing_fields;
        assert!(
            report.loaded * 100 >= total * 95,
            "≥95% of curated rules should load in the engine, got {report:?}"
        );
    }

    #[test]
    fn load_fixture_dir_reports_skips() {
        // Real-rule-shaped fixtures: 3 loadable + 1 skipped (uses Hashes).
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sigma");
        let (rules, report) = load_rules(&dir);
        assert_eq!(report.loaded, 3, "3 fixtures should compile");
        assert_eq!(report.skipped_missing_fields, 1, "the Hashes rule should be skipped");
        // The encoded-powershell rule's OR-of-maps selection compiled and matches.
        let ps = rules
            .iter()
            .find(|r| r.title.contains("Encoded PowerShell"))
            .expect("powershell rule loaded");
        assert!(ps.eval(&fields(&[
            ("Image", "C:\\Windows\\System32\\pwsh.exe"),
            ("CommandLine", "pwsh -ec ZQBjAGgAbwA="),
        ])));
    }

    #[test]
    fn base64_and_windash_transforms() {
        // base64 of a literal, matched with contains.
        assert_eq!(B64.encode(b"whoami"), "d2hvYW1p");
        let yaml = r#"
title: Encoded keyword
id: 88888888-8888-8888-8888-888888888888
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|base64offset|contains: 'whoami'
    selection2:
        CommandLine|windash|contains: '-enc'
    condition: selection or selection2
"#;
        let rule = compile_str(yaml).expect("compile");
        // windash: '/enc' should match the '-enc' windash pattern.
        assert!(rule.eval(&fields(&[("CommandLine", "powershell /enc ABCD")])));
        // base64offset: 'whoami' base64-embedded somewhere.
        let embedded = format!("powershell -e {}", B64.encode(b"XXwhoami"));
        assert!(rule.eval(&fields(&[("CommandLine", &embedded)])));
    }
}
