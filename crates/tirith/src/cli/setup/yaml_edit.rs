//! Comment- and layout-preserving edits of one owned field in a YAML policy.
//!
//! Profile and setting operations own a few fields of the user's policy file.
//! Instead of re-serializing the whole document (which drops comments, blank
//! lines, key order and quoting), an edit rewrites only the lines of the owned
//! field: the scalar on its line, the field's own block, a new line at the end
//! of its parent mapping, or the removal of its lines.
//!
//! Only block-style mappings are navigated. Anything else on the path (flow
//! collections, anchors, tags, multi-line scalars, sequences, tabs, several
//! documents, mixed line endings) is refused with the requested change shown as
//! a diff, so nothing is ever rewritten that the user did not ask for. A
//! leading `---` and a trailing `...` that ends the one document are kept, and
//! lines off the path (a multi-line flow collection closing in its key's
//! column) are left as they are.
//!
//! Every edit is checked: the edited text must parse to exactly the original
//! document with only the owned field changed, and repeat no key. A failed
//! check is a refusal.

use serde_json::Value;

/// Set (`Some`) or remove (`None`) the field named by `pointer` (a validated
/// JSON pointer of plain object keys) in `text`, touching only its lines.
pub(super) fn set_field(
    text: &str,
    pointer: &str,
    value: Option<&Value>,
) -> Result<String, String> {
    let keys: Vec<&str> = pointer.split('/').skip(1).collect();
    let original = parse(text).map_err(|_| "target is not a valid YAML object".to_string())?;
    if !original.is_object() {
        return Err("target is not a valid YAML object".into());
    }
    let mut expected = original.clone();
    set_value(&mut expected, &keys, value);
    let refuse = |reason: &str| refusal(&keys, reason, &original, value);
    if !unique_keys(text) {
        return Err(refuse("a mapping in the file repeats a key"));
    }
    let edited = edit(text, &keys, value).map_err(&refuse)?;
    match parse(&edited) {
        Ok(actual) if actual == expected && unique_keys(&edited) => Ok(edited),
        _ => Err(refuse("the in-place edit could not be verified")),
    }
}

/// The parsed comparison above keeps the last of two equal keys, so it cannot
/// see a repeated key; serde_yaml's own value type refuses one, as the policy
/// loader does. An edit that adds a second entry for a key it did not
/// recognize is therefore refused, never written.
fn unique_keys(text: &str) -> bool {
    text.trim().is_empty() || serde_yaml::from_str::<serde_yaml::Value>(text).is_ok()
}

/// Parse like the change journal does: blank or comment-only text is `{}`.
fn parse(text: &str) -> Result<Value, serde_yaml::Error> {
    if text.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    let value: Value = serde_yaml::from_str(text)?;
    Ok(if value.is_null() {
        serde_json::json!({})
    } else {
        value
    })
}

/// The semantic result the text edit must reach. Removing a missing field is a
/// no-op and never creates its parents.
fn set_value(document: &mut Value, keys: &[&str], value: Option<&Value>) {
    let Some((last, parents)) = keys.split_last() else {
        return;
    };
    let mut current = document;
    for key in parents {
        let Some(object) = current.as_object_mut() else {
            return;
        };
        if value.is_none() && !object.contains_key(*key) {
            return;
        }
        current = object
            .entry((*key).to_owned())
            .or_insert_with(|| serde_json::json!({}));
        // An empty `parent:` (null) becomes the mapping that holds the field.
        if value.is_some() && current.is_null() {
            *current = serde_json::json!({});
        }
    }
    let Some(object) = current.as_object_mut() else {
        return;
    };
    match value {
        Some(value) => {
            object.insert((*last).to_owned(), value.clone());
        }
        None => {
            object.remove(*last);
        }
    }
}

/// The refusal shows the requested change as a diff of the owned field alone:
/// its current and requested value nested under its key path. Other fields of
/// the policy (credentials such as `policy_server_api_key` or webhook headers
/// may sort right next to an owned field) never appear in the message.
fn refusal(keys: &[&str], reason: &str, document: &Value, requested: Option<&Value>) -> String {
    let render = |value: Option<&Value>| match value {
        Some(value) => serde_yaml::to_string(&nest(keys, value)).unwrap_or_default(),
        None => String::new(),
    };
    let current = keys
        .iter()
        .try_fold(document, |value, key| value.as_object()?.get(*key));
    let (before, after) = (render(current), render(requested));
    let before: Vec<&str> = before.lines().collect();
    let after: Vec<&str> = after.lines().collect();
    let prefix = before
        .iter()
        .zip(&after)
        .take_while(|(left, right)| left == right)
        .count();
    let suffix = before[prefix..]
        .iter()
        .rev()
        .zip(after[prefix..].iter().rev())
        .take_while(|(left, right)| left == right)
        .count();
    let mut diff = String::from("--- current (normalized)\n+++ requested (normalized)\n");
    for line in &before[..prefix] {
        diff.push_str(&format!("  {line}\n"));
    }
    for line in &before[prefix..before.len() - suffix] {
        diff.push_str(&format!("- {line}\n"));
    }
    for line in &after[prefix..after.len() - suffix] {
        diff.push_str(&format!("+ {line}\n"));
    }
    let tail = before.len() - suffix;
    for line in &before[tail..] {
        diff.push_str(&format!("  {line}\n"));
    }
    format!(
        "cannot change `{}` in place without rewriting other parts of the policy file ({reason}); \
         nothing was changed. Make this change by hand, or rewrite that part of the file in plain \
         block style, then retry:\n{diff}",
        keys.join(".")
    )
}

#[derive(Clone, Copy, PartialEq)]
enum Style {
    Plain,
    Single,
    Double,
}

/// What follows `key:` on a key line.
enum Rest {
    /// Nothing, or only a comment starting at the given column.
    Empty {
        comment: Option<usize>,
    },
    /// `{}` with an optional comment.
    EmptyMap {
        comment: Option<usize>,
    },
    /// `[]` with an optional comment.
    EmptySeq {
        comment: Option<usize>,
    },
    /// A one-line scalar ending before the given comment column.
    Scalar {
        style: Style,
        comment: Option<usize>,
    },
    Complex,
}

struct Entry {
    key: String,
    /// The key line.
    line: usize,
    /// One past the last content line of the entry (comments after the last
    /// content line belong to whatever follows).
    end: usize,
    /// Byte column just past the `:`.
    colon: usize,
}

struct Document {
    lines: Vec<String>,
    eol: &'static str,
    final_newline: bool,
    /// First line of the root mapping (after a leading `---`).
    root: usize,
    step: usize,
    /// A trailing `...` document-end marker and the comment or blank lines
    /// after it, written back unchanged after the content.
    trailer: Vec<String>,
}

type Refusal = &'static str;

fn edit(text: &str, keys: &[&str], value: Option<&Value>) -> Result<String, Refusal> {
    let mut document = Document::read(text)?;
    document.edit(keys, value)?;
    Ok(document.write())
}

impl Document {
    fn read(text: &str) -> Result<Self, Refusal> {
        let crlf = text.matches("\r\n").count();
        let lf = text.matches('\n').count();
        let cr = text.matches('\r').count();
        let eol = if crlf > 0 { "\r\n" } else { "\n" };
        if (crlf > 0 && crlf != lf) || cr != crlf {
            return Err("the file mixes line endings");
        }
        let mut lines: Vec<String> = text.split(eol).map(str::to_owned).collect();
        let final_newline = text.is_empty() || text.ends_with(eol);
        if final_newline {
            lines.pop();
        }
        if lines
            .iter()
            .any(|line| line.trim_start_matches(' ').starts_with('\t'))
        {
            return Err("tab indentation is not supported");
        }
        // A single leading `---` is allowed, and so is a trailing `...` with
        // only comments after it (it ends the one document); directives and
        // further documents are not.
        let root = lines
            .iter()
            .position(|line| !is_blank_or_comment(line))
            .filter(|at| lines[*at].trim_end_matches(' ') == "---")
            .map_or(0, |at| at + 1);
        let end_marker = lines
            .iter()
            .rposition(|line| !is_blank_or_comment(line))
            .filter(|at| *at >= root && is_document_end(&lines[*at]));
        let trailer = end_marker.map_or_else(Vec::new, |at| lines.split_off(at));
        if lines.iter().enumerate().any(|(at, line)| {
            line.starts_with('%')
                || (at >= root && (line.starts_with("---") || line.starts_with("...")))
        }) {
            return Err("directives or several YAML documents are not supported");
        }
        let step = detect_step(&lines[root..]);
        Ok(Self {
            lines,
            eol,
            final_newline,
            root,
            step,
            trailer,
        })
    }

    fn write(&self) -> String {
        let lines: Vec<&str> = self
            .lines
            .iter()
            .chain(&self.trailer)
            .map(String::as_str)
            .collect();
        let mut text = lines.join(self.eol);
        if self.final_newline && !lines.is_empty() {
            text.push_str(self.eol);
        }
        text
    }

    fn edit(&mut self, keys: &[&str], value: Option<&Value>) -> Result<(), Refusal> {
        if let Some(line) = self.empty_flow_root() {
            // `{}` as the whole document: the first field replaces it.
            let Some(value) = value else {
                return Ok(());
            };
            let comment = rest_comment(&self.lines[line], &classify(&self.lines[line], 0));
            let rendered =
                self.render_entry(&render_key(keys[0])?, &nest(&keys[1..], value), 0, comment)?;
            self.splice(line, line + 1, rendered);
            return Ok(());
        }
        let (mut start, mut end, mut indent) = (self.root, self.lines.len(), 0usize);
        let mut parent: Option<usize> = None;
        for (depth, key) in keys.iter().enumerate() {
            let entries = self.entries(start, end, indent)?;
            let Some(entry) = entries.iter().find(|entry| entry.key == *key) else {
                let Some(value) = value else {
                    return Ok(());
                };
                // Insert the missing remainder at the end of this mapping.
                let at = entries
                    .last()
                    .map(|entry| entry.end)
                    .or(parent.map(|line| line + 1))
                    .unwrap_or(self.lines.len());
                let nested = nest(&keys[depth + 1..], value);
                let rendered = self.render_entry(&render_key(key)?, &nested, indent, None)?;
                self.insert(at, rendered);
                return Ok(());
            };
            let rest = classify(&self.lines[entry.line][entry.colon..], entry.colon);
            if depth + 1 == keys.len() {
                return self.replace(entry, &entries, indent, parent, value);
            }
            let has_children = entry.end > entry.line + 1;
            match rest {
                Rest::Empty { .. } if has_children => {
                    let first = (entry.line + 1..entry.end)
                        .find(|line| !is_blank_or_comment(&self.lines[*line]))
                        .ok_or("unexpected empty block")?;
                    let child = indent_of(&self.lines[first]);
                    if child <= indent || is_sequence_item(&self.lines[first][child..]) {
                        return Err("a parent on the path is not a block mapping");
                    }
                    parent = Some(entry.line);
                    start = entry.line + 1;
                    end = entry.end;
                    indent = child;
                }
                Rest::Empty { .. } | Rest::EmptyMap { .. } => {
                    let Some(value) = value else {
                        return Ok(());
                    };
                    let nested = nest(&keys[depth + 1..], value);
                    let raw_key = self.lines[entry.line][..entry.colon - 1]
                        .trim_start()
                        .to_owned();
                    let comment = rest_comment(&self.lines[entry.line], &rest);
                    let rendered = self.render_entry(&raw_key, &nested, indent, comment)?;
                    self.splice(entry.line, entry.end, rendered);
                    return Ok(());
                }
                _ => return Err("a parent on the path is not a block mapping"),
            }
        }
        Ok(())
    }

    fn replace(
        &mut self,
        entry: &Entry,
        entries: &[Entry],
        indent: usize,
        parent: Option<usize>,
        value: Option<&Value>,
    ) -> Result<(), Refusal> {
        let line = &self.lines[entry.line];
        if value.is_some() && line[entry.colon..].contains('\t') {
            // Comments and values are only located after spaces here, so a
            // rewrite of this line could drop a comment written after a tab.
            return Err("a tab follows the field's key");
        }
        let rest = classify(&line[entry.colon..], entry.colon);
        let Some(value) = value else {
            self.splice(entry.line, entry.end, Vec::new());
            if entries.len() == 1 {
                match parent {
                    Some(parent) => self.fill_empty_map(parent)?,
                    None => self.fill_empty_root(),
                }
            }
            return Ok(());
        };
        let raw_key = line[..entry.colon - 1].trim_start().to_owned();
        let comment = rest_comment(line, &rest);
        let mut rendered = self.render_entry(&raw_key, value, indent, comment)?;
        // Keep the quoting style of a one-line string value.
        if let (Rest::Scalar { style, .. }, Value::String(text)) = (&rest, value) {
            if entry.end == entry.line + 1 && rendered.len() == 1 {
                if let Some(quoted) = quote(text, *style) {
                    let mut first = format!("{}{raw_key}: {quoted}", " ".repeat(indent));
                    if let Some(comment) = comment {
                        first.push_str(comment);
                    }
                    rendered = vec![first];
                }
            }
        }
        self.splice(entry.line, entry.end, rendered);
        Ok(())
    }

    /// The entries of the block mapping at `indent` in `start..end`.
    fn entries(&self, start: usize, end: usize, indent: usize) -> Result<Vec<Entry>, Refusal> {
        let mut entries: Vec<Entry> = Vec::new();
        for index in start..end {
            let line = &self.lines[index];
            if is_blank_or_comment(line) {
                continue;
            }
            let column = indent_of(line);
            if column > indent {
                let entry = entries.last_mut().ok_or("unexpected indentation")?;
                entry.end = index + 1;
                continue;
            }
            if column < indent {
                return Err("unexpected indentation");
            }
            let content = &line[column..];
            if is_sequence_item(content) {
                // `key:` followed by a sequence at the same indentation.
                let entry = entries.last_mut().ok_or("the document is not a mapping")?;
                let rest = &self.lines[entry.line][entry.colon..];
                if !matches!(classify(rest, entry.colon), Rest::Empty { .. }) {
                    return Err("the document is not a block mapping");
                }
                entry.end = index + 1;
                continue;
            }
            let Some((key, colon)) = parse_key(content) else {
                // Not a plain or quoted key: the line continues the previous
                // entry's value, such as the closing `]` / `}` (or an item) of
                // a multi-line flow collection written in the key's column.
                // A line that may still be a key (anchored, tagged, alias or
                // complex) is refused, so an edit can never add a second
                // entry for a key it did not see. The edited text is
                // re-parsed and compared, so a wrong boundary can only refuse.
                if content.starts_with(|first: char| "?&*!|>%@`-:".contains(first)) {
                    return Err("a key is not a plain or quoted key");
                }
                let entry = entries
                    .last_mut()
                    .ok_or("a key is not a plain or quoted key")?;
                entry.end = index + 1;
                continue;
            };
            entries.push(Entry {
                key,
                line: index,
                end: index + 1,
                colon: column + colon,
            });
        }
        Ok(entries)
    }

    fn render_entry(
        &self,
        raw_key: &str,
        value: &Value,
        indent: usize,
        comment: Option<&str>,
    ) -> Result<Vec<String>, Refusal> {
        let pad = " ".repeat(indent);
        let block = match value {
            Value::Object(map) => !map.is_empty(),
            Value::Array(items) => !items.is_empty(),
            _ => false,
        };
        let rendered = match value {
            Value::Object(map) if map.is_empty() => "{}\n".to_owned(),
            Value::Array(items) if items.is_empty() => "[]\n".to_owned(),
            value => serde_yaml::to_string(value).map_err(|_| "the value cannot be written")?,
        };
        let mut lines = Vec::new();
        let mut rendered_lines = rendered.lines();
        let mut first = format!("{pad}{raw_key}:");
        if !block {
            first.push(' ');
            first.push_str(rendered_lines.next().unwrap_or("null"));
        }
        if let Some(comment) = comment {
            first.push_str(comment);
        }
        lines.push(first);
        let child = if block {
            " ".repeat(indent + self.step)
        } else {
            pad
        };
        for line in rendered_lines {
            lines.push(if line.is_empty() {
                String::new()
            } else {
                format!("{child}{line}")
            });
        }
        Ok(lines)
    }

    fn splice(&mut self, start: usize, end: usize, lines: Vec<String>) {
        self.lines.splice(start..end, lines);
    }

    fn insert(&mut self, at: usize, lines: Vec<String>) {
        self.splice(at, at, lines);
    }

    /// `parent:` lost its last child: keep it a mapping as `parent: {}`.
    fn fill_empty_map(&mut self, parent: usize) -> Result<(), Refusal> {
        let line = &self.lines[parent];
        let column = indent_of(line);
        let (_, colon) = parse_key(&line[column..]).ok_or("unexpected parent line")?;
        let colon = column + colon;
        let comment = rest_comment(line, &classify(&line[colon..], colon)).unwrap_or("");
        self.lines[parent] = format!("{}: {{}}{comment}", &line[..colon - 1]);
        Ok(())
    }

    /// The line of a document that is only `{}` (plus comments).
    fn empty_flow_root(&self) -> Option<usize> {
        let mut content =
            (self.root..self.lines.len()).filter(|line| !is_blank_or_comment(&self.lines[*line]));
        let line = content.next()?;
        (content.next().is_none()
            && matches!(classify(&self.lines[line], 0), Rest::EmptyMap { .. }))
        .then_some(line)
    }

    /// Removing the last root key must leave a mapping, not an empty document.
    fn fill_empty_root(&mut self) {
        if self.lines[self.root..]
            .iter()
            .all(|line| is_blank_or_comment(line))
        {
            self.lines.push("{}".into());
            self.final_newline = true;
        }
    }
}

/// The text from the whitespace before a comment to the end of the line.
fn rest_comment<'a>(line: &'a str, rest: &Rest) -> Option<&'a str> {
    let at = match rest {
        Rest::Empty { comment }
        | Rest::EmptyMap { comment }
        | Rest::EmptySeq { comment }
        | Rest::Scalar { comment, .. } => (*comment)?,
        Rest::Complex => return None,
    };
    let before = &line[..at];
    Some(&line[before.trim_end_matches(' ').len()..])
}

fn nest(keys: &[&str], value: &Value) -> Value {
    keys.iter().rev().fold(value.clone(), |inner, key| {
        let mut map = serde_json::Map::new();
        map.insert((*key).to_owned(), inner);
        Value::Object(map)
    })
}

fn render_key(key: &str) -> Result<String, Refusal> {
    let rendered = serde_yaml::to_string(&Value::String(key.to_owned()))
        .map_err(|_| "the key cannot be written")?;
    let rendered = rendered.trim_end_matches('\n');
    if rendered.contains('\n') {
        return Err("the key cannot be written on one line");
    }
    Ok(rendered.to_owned())
}

fn quote(text: &str, style: Style) -> Option<String> {
    if text.chars().any(char::is_control) {
        return None;
    }
    match style {
        Style::Plain => None,
        Style::Single => Some(format!("'{}'", text.replace('\'', "''"))),
        Style::Double => serde_json::to_string(text).ok(),
    }
}

fn detect_step(lines: &[String]) -> usize {
    let mut previous: Option<usize> = None;
    for line in lines {
        if is_blank_or_comment(line) {
            continue;
        }
        let column = indent_of(line);
        if let Some(parent) = previous {
            if column > parent && !is_sequence_item(&line[column..]) {
                return column - parent;
            }
        }
        let content = &line[column..];
        previous = parse_key(content)
            .filter(|(_, colon)| {
                matches!(
                    classify(&content[*colon..], column + colon),
                    Rest::Empty { .. }
                )
            })
            .map(|_| column);
    }
    2
}

/// A `...` document-end marker line, optionally followed by a comment.
fn is_document_end(line: &str) -> bool {
    line.strip_prefix("...").is_some_and(|rest| {
        let trimmed = rest.trim_start_matches(' ');
        trimmed.is_empty() || (trimmed.len() < rest.len() && trimmed.starts_with('#'))
    })
}

fn is_blank_or_comment(line: &str) -> bool {
    let trimmed = line.trim_start_matches(' ');
    trimmed.is_empty() || trimmed.starts_with('#')
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

fn is_sequence_item(content: &str) -> bool {
    content == "-" || content.starts_with("- ")
}

/// A plain or quoted key followed by `:`. Returns the decoded key and the byte
/// offset just past the colon. Spaces or tabs may separate the key from the
/// `:` and the `:` from the value, as in YAML.
fn parse_key(content: &str) -> Option<(String, usize)> {
    let followed_by_separator = |at: usize| {
        content[at..].starts_with(':')
            && content[at + 1..]
                .chars()
                .next()
                .is_none_or(|next| next == ' ' || next == '\t')
    };
    let first = content.chars().next()?;
    let (key, end) = match first {
        '\'' | '"' => {
            let close = closing_quote(content)?;
            let raw = &content[..close];
            let key: String = serde_yaml::from_str(raw).ok()?;
            let after = raw.len();
            let blanks =
                content[after..].len() - content[after..].trim_start_matches([' ', '\t']).len();
            (key, after + blanks)
        }
        _ => {
            if "-?:,[]{}#&*!|>%@`".contains(first) {
                return None;
            }
            let at = content
                .char_indices()
                .find(|(at, _)| followed_by_separator(*at))
                .map(|(at, _)| at)?;
            let key = content[..at].trim_end_matches([' ', '\t']);
            if key.contains(" #") || key.contains("\t#") {
                return None;
            }
            (key.to_owned(), at)
        }
    };
    followed_by_separator(end).then_some((key, end + 1))
}

/// Byte offset just past the closing quote of a quoted scalar at the start.
fn closing_quote(text: &str) -> Option<usize> {
    let quote = text.chars().next()?;
    let mut chars = text.char_indices().skip(1).peekable();
    while let Some((at, ch)) = chars.next() {
        if quote == '"' && ch == '\\' {
            chars.next();
        } else if ch == quote {
            if quote == '\'' && chars.peek().is_some_and(|(_, next)| *next == '\'') {
                chars.next();
            } else {
                return Some(at + 1);
            }
        }
    }
    None
}

/// Classify the text after `key:`; `offset` is its column in the line.
fn classify(rest: &str, offset: usize) -> Rest {
    let value_start = rest.len() - rest.trim_start_matches(' ').len();
    let value = &rest[value_start..];
    let comment_at = |at: usize| Some(offset + value_start + at);
    if value.is_empty() {
        return Rest::Empty { comment: None };
    }
    if value.starts_with('#') {
        return Rest::Empty {
            comment: comment_at(0),
        };
    }
    // After a value: spaces, then nothing or a comment.
    let tail = |after: usize| -> Option<Option<usize>> {
        let tail = &value[after..];
        let trimmed = tail.trim_start_matches(' ');
        if trimmed.is_empty() {
            Some(None)
        } else if trimmed.starts_with('#') && trimmed.len() < tail.len() {
            Some(comment_at(after + tail.len() - trimmed.len()))
        } else {
            None
        }
    };
    if let Some(after) = value.strip_prefix("{}") {
        return match tail(value.len() - after.len()) {
            Some(comment) => Rest::EmptyMap { comment },
            None => Rest::Complex,
        };
    }
    if let Some(after) = value.strip_prefix("[]") {
        return match tail(value.len() - after.len()) {
            Some(comment) => Rest::EmptySeq { comment },
            None => Rest::Complex,
        };
    }
    let first = value.chars().next().unwrap_or(' ');
    if first == '\'' || first == '"' {
        let style = if first == '\'' {
            Style::Single
        } else {
            Style::Double
        };
        return match closing_quote(value).and_then(tail) {
            Some(comment) => Rest::Scalar { style, comment },
            None => Rest::Complex,
        };
    }
    if "{[|>&*!%@`".contains(first) || is_sequence_item(value) || value.starts_with("? ") {
        return Rest::Complex;
    }
    let end = value.find(" #").map(|at| at + 1).unwrap_or(value.len());
    Rest::Scalar {
        style: Style::Plain,
        comment: (end < value.len()).then(|| offset + value_start + end),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn set(text: &str, pointer: &str, value: Value) -> String {
        set_field(text, pointer, Some(&value)).unwrap()
    }

    fn remove(text: &str, pointer: &str) -> String {
        set_field(text, pointer, None).unwrap()
    }

    #[test]
    fn scalar_edits_keep_comments_blank_lines_and_key_order() {
        let text = "# header\n\nzeta: 1   # z first\n\n# about fail mode\nfail_mode: open # inline\nalpha: true\n";
        assert_eq!(
            set(text, "/fail_mode", json!("closed")),
            "# header\n\nzeta: 1   # z first\n\n# about fail mode\nfail_mode: closed # inline\nalpha: true\n"
        );
        assert_eq!(
            set(text, "/zeta", json!(3)),
            "# header\n\nzeta: 3   # z first\n\n# about fail mode\nfail_mode: open # inline\nalpha: true\n"
        );
        assert_eq!(
            set(text, "/strict_warn", json!(false)),
            format!("{text}strict_warn: false\n")
        );
    }

    #[test]
    fn quoting_styles_of_values_and_keys_are_kept() {
        let text = "'fail_mode': 'open'\n\"paranoia\": 2\nmode: \"warn\"   # dq\nplain: text\n";
        let edited = set(text, "/fail_mode", json!("closed"));
        assert_eq!(
            edited,
            "'fail_mode': 'closed'\n\"paranoia\": 2\nmode: \"warn\"   # dq\nplain: text\n"
        );
        assert_eq!(
            set(&edited, "/mode", json!("it's \"x\"")),
            "'fail_mode': 'closed'\n\"paranoia\": 2\nmode: \"it's \\\"x\\\"\"   # dq\nplain: text\n"
        );
        assert_eq!(
            set(text, "/paranoia", json!(4)),
            "'fail_mode': 'open'\n\"paranoia\": 4\nmode: \"warn\"   # dq\nplain: text\n"
        );
        // A string that would read as another type is quoted, not left plain.
        assert_eq!(
            set(text, "/plain", json!("true")),
            "'fail_mode': 'open'\n\"paranoia\": 2\nmode: \"warn\"   # dq\nplain: 'true'\n"
        );
    }

    #[test]
    fn nested_maps_insert_replace_and_remove_inside_their_block() {
        let text = "severity_overrides:   # mine\n    # four-space indentation\n    shortened_url: low\n\nscan:\n    require_complete: false\nlast: 1\n";
        let added = set(
            text,
            "/severity_overrides/plain_http_to_sink",
            json!("high"),
        );
        assert_eq!(
            added,
            "severity_overrides:   # mine\n    # four-space indentation\n    shortened_url: low\n    plain_http_to_sink: high\n\nscan:\n    require_complete: false\nlast: 1\n"
        );
        // Removing what was inserted restores the exact bytes.
        assert_eq!(
            remove(&added, "/severity_overrides/plain_http_to_sink"),
            text
        );
        assert_eq!(
            set(text, "/scan/require_complete", json!(true)),
            text.replace("require_complete: false", "require_complete: true")
        );
        // A missing parent is created with the file's own indentation step.
        assert_eq!(
            set(text, "/action_overrides/shortened_url", json!("warn")),
            format!("{text}action_overrides:\n    shortened_url: warn\n")
        );
        // Removing the last child keeps the parent a mapping and its comment.
        assert_eq!(
            remove(text, "/severity_overrides/shortened_url"),
            "severity_overrides: {}   # mine\n    # four-space indentation\n\nscan:\n    require_complete: false\nlast: 1\n"
        );
        // Removing a missing field changes nothing.
        assert_eq!(remove(text, "/action_overrides/x"), text);
        assert_eq!(remove(text, "/scan/missing"), text);
    }

    #[test]
    fn empty_mapping_parent_gains_a_block_child() {
        assert_eq!(
            set(
                "severity_overrides: {}  # none yet\nb: 1\n",
                "/severity_overrides/x",
                json!("low")
            ),
            "severity_overrides:  # none yet\n  x: low\nb: 1\n"
        );
        assert_eq!(
            set(
                "severity_overrides:\nb: 1\n",
                "/severity_overrides/x",
                json!("low")
            ),
            "severity_overrides:\n  x: low\nb: 1\n"
        );
    }

    #[test]
    fn owned_block_values_are_replaced_whole_and_neighbours_kept() {
        let text = "# top\nprotection_profile:  # managed by tirith\n  name: comfortable\n  version: 1\n  owned_fields:\n  - fail_mode\n# next section\nparanoia: 2\n";
        let profile =
            json!({"name": "strict", "version": 1, "owned_fields": ["fail_mode", "paranoia"]});
        assert_eq!(
            set(text, "/protection_profile", profile),
            "# top\nprotection_profile:  # managed by tirith\n  name: strict\n  owned_fields:\n  - fail_mode\n  - paranoia\n  version: 1\n# next section\nparanoia: 2\n"
        );
        assert_eq!(
            remove(text, "/protection_profile"),
            "# top\n# next section\nparanoia: 2\n"
        );
        // A one-line flow value of the owned field itself is simply replaced.
        assert_eq!(
            set(
                "approval_rules: []  # none\nx: 1\n",
                "/approval_rules",
                json!([])
            ),
            "approval_rules: []  # none\nx: 1\n"
        );
    }

    #[test]
    fn crlf_missing_final_newline_and_document_marker_are_kept() {
        let text = "# windows\r\nfail_mode: open\r\nscan:\r\n  require_complete: false\r\n";
        assert_eq!(
            set(text, "/scan/require_complete", json!(true)),
            "# windows\r\nfail_mode: open\r\nscan:\r\n  require_complete: true\r\n"
        );
        assert_eq!(
            set(text, "/strict_warn", json!(true)),
            format!("{text}strict_warn: true\r\n")
        );
        assert_eq!(
            set("---\nfail_mode: open", "/fail_mode", json!("closed")),
            "---\nfail_mode: closed"
        );
        assert_eq!(
            set("---\nfail_mode: open", "/paranoia", json!(3)),
            "---\nfail_mode: open\nparanoia: 3"
        );
    }

    /// A trailing `...` document-end marker (with comments after it) ends the
    /// only document, so it is kept and edits stay before it. Every edit
    /// undone restores the exact bytes.
    #[test]
    fn trailing_document_end_marker_is_kept_and_edits_stay_before_it() {
        let text = "fail_mode: open\nscan:\n  require_complete: false\n...\n# after the end\n";
        let edited = set(text, "/fail_mode", json!("closed"));
        assert_eq!(
            edited,
            "fail_mode: closed\nscan:\n  require_complete: false\n...\n# after the end\n"
        );
        assert_eq!(set(&edited, "/fail_mode", json!("open")), text);
        let nested = set(text, "/scan/require_complete", json!(true));
        assert_eq!(nested, text.replace("complete: false", "complete: true"));
        assert_eq!(set(&nested, "/scan/require_complete", json!(false)), text);
        let added = set(text, "/strict_warn", json!(true));
        assert_eq!(
            added,
            "fail_mode: open\nscan:\n  require_complete: false\nstrict_warn: true\n...\n# after the end\n"
        );
        assert_eq!(remove(&added, "/strict_warn"), text);
        let created = set(text, "/action_overrides/shortened_url", json!("warn"));
        assert_eq!(
            created,
            "fail_mode: open\nscan:\n  require_complete: false\naction_overrides:\n  shortened_url: warn\n...\n# after the end\n"
        );

        // Marker forms: with a comment, without a final newline, CRLF, after `---`.
        assert_eq!(
            set("a: 1\n... # end\n", "/a", json!(2)),
            "a: 2\n... # end\n"
        );
        assert_eq!(set("a: 1\n...", "/a", json!(2)), "a: 2\n...");
        assert_eq!(set("a: 1\n...", "/b", json!(2)), "a: 1\nb: 2\n...");
        assert_eq!(
            set("a: 1\r\n...\r\n", "/b", json!(2)),
            "a: 1\r\nb: 2\r\n...\r\n"
        );
        assert_eq!(set("---\na: 1\n...\n", "/a", json!(2)), "---\na: 2\n...\n");
        // Emptied or empty documents stay mappings before the marker.
        assert_eq!(remove("a: 1\n...\n", "/a"), "{}\n...\n");
        assert_eq!(set("{}\n...\n", "/a", json!(1)), "a: 1\n...\n");
        assert_eq!(set("---\n...\n", "/a", json!(1)), "---\na: 1\n...\n");

        // Content after the marker is another document: still refused.
        for text in [
            "a: 1\n...\nb: 2\n",
            "a: 1\n...\n---\nb: 2\n",
            "a: 1\n...\n%YAML 1.2\n---\nb: 2\n",
        ] {
            let result = set_field(text, "/a", Some(&json!(2)));
            assert!(result.is_err(), "{text:?} -> {result:?}");
        }
    }

    /// A multi-line flow collection may close (or list its items) in the
    /// column of its key. Such a line continues that entry; it is not a
    /// reason to refuse an edit of another field.
    #[test]
    fn flow_collection_lines_in_the_key_column_belong_to_their_entry() {
        let flow =
            "allowlist: [\n  \"a.example\",\n  \"b.example\"\n]\n# mode\nfail_mode: open  # x\n";
        let edited = set(flow, "/fail_mode", json!("closed"));
        assert_eq!(edited, flow.replace("fail_mode: open", "fail_mode: closed"));
        assert_eq!(set(&edited, "/fail_mode", json!("open")), flow);
        let added = set(flow, "/strict_warn", json!(true));
        assert_eq!(added, format!("{flow}strict_warn: true\n"));
        assert_eq!(remove(&added, "/strict_warn"), flow);

        // The flow collection as the last entry: new keys go after its closer.
        let last = "fail_mode: open\nblocklist: {\n  a.example: x\n}\n";
        let added = set(last, "/strict_warn", json!(true));
        assert_eq!(added, format!("{last}strict_warn: true\n"));
        assert_eq!(remove(&added, "/strict_warn"), last);

        // Items in the key column too.
        let items = "allowlist: [\n\"a.example\",\n\"b.example\"\n]\nfail_mode: open\n";
        assert_eq!(
            set(items, "/fail_mode", json!("closed")),
            items.replace("open", "closed")
        );

        // Inside a nested mapping the closer sits in that mapping's column.
        let nested = "scan:\n  require_complete: false\n  extra: [\n    1\n  ]\nfail_mode: open\n";
        let edited = set(nested, "/scan/require_complete", json!(true));
        assert_eq!(edited, nested.replace("false", "true"));
        assert_eq!(set(&edited, "/scan/require_complete", json!(false)), nested);
        let added = set(nested, "/scan/fast", json!(true));
        assert_eq!(
            added,
            "scan:\n  require_complete: false\n  extra: [\n    1\n  ]\n  fast: true\nfail_mode: open\n"
        );
        assert_eq!(remove(&added, "/scan/fast"), nested);

        // The owned field itself: its whole entry, closer included, is replaced.
        assert_eq!(
            set(flow, "/allowlist", json!(["c.example"])),
            "allowlist:\n  - c.example\n# mode\nfail_mode: open  # x\n"
        );
        // A key line this parser cannot read stays a refusal, so no second
        // entry is ever added for it.
        for (text, pointer) in [
            ("a: 1\n!!str b: 2\n", "/b"),
            ("a: 1\n&x b: 2\nc: 3\n", "/c"),
            ("a: 1\n? b\n: 2\n", "/b"),
            // A tab-separated key after a key-column flow closer is a key.
            ("allowlist: [\n  \"a.example\"\n]\nb:\t2\n", "/b"),
        ] {
            let result = set_field(text, pointer, Some(&json!(3)));
            assert!(result.is_err(), "{text:?} {pointer} -> {result:?}");
        }
        // A tab after a key-column closer only separates a comment.
        let closer = "allowlist: [\n  \"a.example\"\n]\t# end\nb: 1\n";
        assert_eq!(set(closer, "/b", json!(3)), closer.replace("b: 1", "b: 3"));
        // A flow collection on the path is still refused.
        assert!(set_field(
            "severity_overrides: {\n  a: low\n}\nb: 1\n",
            "/severity_overrides/x",
            Some(&json!("high"))
        )
        .is_err());
    }

    /// YAML separates a key from `:` and `:` from its value with spaces or
    /// tabs. A key line using a tab was not seen as a key, so setting that
    /// key appended a second entry (`paranoia:\t1` then `paranoia: 3`), the
    /// check passed because the last duplicate wins, and the policy loader
    /// then refused the file and every command was blocked.
    #[test]
    fn tab_separated_keys_are_seen_so_no_second_entry_is_added() {
        let duplicate_free = |text: &str| serde_yaml::from_str::<serde_yaml::Value>(text).is_ok();
        for (text, pointer, value) in [
            ("fail_mode: open\nparanoia:\t1\n", "/paranoia", json!(3)),
            (
                "allow_bypass_env: false\nfail_mode:\topen\n",
                "/fail_mode",
                json!("closed"),
            ),
            ("fail_mode: open\n\"paranoia\":\t1\n", "/paranoia", json!(3)),
            ("fail_mode: open\nparanoia\t: 1\n", "/paranoia", json!(3)),
            (
                "fail_mode: open\n\"paranoia\"\t: 1\n",
                "/paranoia",
                json!(3),
            ),
            (
                "scan:\n  fast: true\n  require_complete:\tfalse\n",
                "/scan/require_complete",
                json!(true),
            ),
            ("parent:\t\n  child: 1\n", "/parent/child", json!(2)),
        ] {
            match set_field(text, pointer, Some(&value)) {
                Ok(edited) => {
                    assert!(duplicate_free(&edited), "{text:?} {pointer} -> {edited:?}");
                    assert_eq!(
                        edited
                            .matches(&pointer[pointer.rfind('/').unwrap() + 1..])
                            .count(),
                        1,
                        "{text:?} -> {edited:?}"
                    );
                }
                Err(reason) => assert!(reason.contains("nothing was changed"), "{reason}"),
            }
        }
        // A tab after the colon: the value on that line is not rewritten (a
        // comment after a tab would be lost), so setting it is refused.
        for (text, pointer) in [
            ("fail_mode: open\nparanoia:\t1\n", "/paranoia"),
            ("fail_mode: open\n\"paranoia\":\t1  # two\n", "/paranoia"),
            (
                "scan:\n  require_complete:\tfalse\n",
                "/scan/require_complete",
            ),
        ] {
            let result = set_field(text, pointer, Some(&json!(3)));
            assert!(result.is_err(), "{text:?} {pointer} -> {result:?}");
        }
        // The key itself is seen: other edits and removal work, in place.
        let tabbed = "fail_mode: open\nparanoia:\t1\t# tabbed\n";
        assert_eq!(
            set(tabbed, "/fail_mode", json!("closed")),
            "fail_mode: closed\nparanoia:\t1\t# tabbed\n"
        );
        assert_eq!(
            set(tabbed, "/strict_warn", json!(true)),
            format!("{tabbed}strict_warn: true\n")
        );
        assert_eq!(remove(tabbed, "/paranoia"), "fail_mode: open\n");
        // A tab before the colon is part of the separation, not the key.
        assert_eq!(
            set("fail_mode: open\nparanoia\t: 1\n", "/paranoia", json!(3)),
            "fail_mode: open\nparanoia\t: 3\n"
        );
        assert_eq!(
            set("\"paranoia\"\t: 1  # q\n", "/paranoia", json!(3)),
            "\"paranoia\"\t: 3  # q\n"
        );
    }

    /// The check after an edit compares the parsed result, where the last of
    /// two equal keys wins, so it must also refuse duplicate keys: a written
    /// duplicate makes the policy loader refuse the whole file.
    #[test]
    fn an_edit_that_would_leave_a_duplicate_key_is_refused() {
        for (text, pointer) in [
            ("a: 1\na: 1\n", "/b"),
            ("a: 1\n\"a\": 1\n", "/b"),
            ("s:\n  b: 1\n  b: 1\nc: 1\n", "/c"),
            ("s:\n  b: 1\n  'b': 1\n", "/s/d"),
        ] {
            let result = set_field(text, pointer, Some(&json!(2)));
            assert!(result.is_err(), "{text:?} {pointer} -> {result:?}");
        }
        assert_eq!(set("a: 1\nb: 1\n", "/c", json!(2)), "a: 1\nb: 1\nc: 2\n");
    }

    #[test]
    fn empty_flow_document_takes_its_first_field() {
        assert_eq!(
            set("{}\n", "/allow_bypass_env", json!(true)),
            "allow_bypass_env: true\n"
        );
        assert_eq!(
            set("# org\n{}   # empty for now\n", "/a/b", json!("x")),
            "# org\na:   # empty for now\n  b: x\n"
        );
        assert_eq!(remove("{}\n", "/a"), "{}\n");
    }

    #[test]
    fn new_and_emptied_documents_stay_mappings() {
        assert_eq!(set("", "/strict_warn", json!(true)), "strict_warn: true\n");
        assert_eq!(
            set("# only a comment\n", "/a/b", json!(1)),
            "# only a comment\na:\n  b: 1\n"
        );
        assert_eq!(remove("strict_warn: true\n", "/strict_warn"), "{}\n");
        assert_eq!(
            remove("# keep\nstrict_warn: true\n", "/strict_warn"),
            "# keep\n{}\n"
        );
    }

    #[test]
    fn unsupported_structure_is_refused_with_the_requested_change_shown() {
        let flow = "severity_overrides: {shortened_url: low}\nfail_mode: open\n";
        let error = set_field(flow, "/severity_overrides/x", Some(&json!("high"))).unwrap_err();
        assert!(
            error.contains("cannot change `severity_overrides.x` in place"),
            "{error}"
        );
        assert!(error.contains("nothing was changed"), "{error}");
        assert!(error.contains("+   x: high"), "{error}");
        // A field that does not exist yet is shown whole as an addition; other
        // entries of its parent are not part of the message.
        assert!(error.contains("+ severity_overrides:\n"), "{error}");
        assert!(!error.contains("shortened_url"), "{error}");
        assert!(!error.contains("fail_mode"), "{error}");

        for (text, pointer) in [
            ("a: &anchor\n  b: 1\nc: *anchor\n", "/a/b"),
            ("a:\n  b: 1\n", "/a/b/c"),
            ("list:\n- a\n- b\n", "/list/x"),
            ("a: 1\r\nb: 2\n", "/a"),
            ("a:\n\tb: 1\n", "/a/b"),
            ("%YAML 1.2\n---\na: 1\n", "/a"),
            ("a: 1\n---\nb: 2\n", "/a"),
            ("? complex\n: 1\n", "/a"),
        ] {
            let result = set_field(text, pointer, Some(&json!(2)));
            assert!(result.is_err(), "{text:?} {pointer} -> {result:?}");
        }
        // An alias to an owned anchored value cannot be silently detached.
        assert!(set_field("a: &x 1\nb: *x\n", "/a", Some(&json!(2))).is_err());
    }

    #[test]
    fn refusal_diff_shows_only_the_owned_field_never_neighbouring_values() {
        // Keys of the normalized document are sorted, so credentials sort right
        // next to owned fields such as `protection_profile` and `scan`.
        let text = "policy_server_api_key: sk-live-SECRET123abc\r\n\
                    policy_server_url: https://policy.example-cli.dev/secret-path\n\
                    protection_profile:\n  name: balanced\n  version: 1\n\
                    scan: {require_complete: false}\n\
                    webhooks:\n- url: https://hooks.example-cli.dev\n  headers:\n    \
                    Authorization: Bearer HEADER-SECRET\n";
        for (pointer, value) in [
            (
                "/protection_profile",
                Some(json!({"name": "strict", "version": 1})),
            ),
            ("/protection_profile", None),
            ("/paranoia", Some(json!(3))),
            ("/scan/require_complete", Some(json!(true))),
            ("/strict_warn", Some(json!(true))),
        ] {
            let error = set_field(text, pointer, value.as_ref()).unwrap_err();
            for secret in ["SECRET123", "secret-path", "HEADER-SECRET", "example-cli"] {
                assert!(!error.contains(secret), "{pointer}: {error}");
            }
            assert!(error.contains("nothing was changed"), "{error}");
        }
        let error = set_field(
            text,
            "/protection_profile",
            Some(&json!({"name": "strict", "version": 1})),
        )
        .unwrap_err();
        assert!(error.contains("  protection_profile:\n"), "{error}");
        assert!(error.contains("-   name: balanced\n"), "{error}");
        assert!(error.contains("+   name: strict\n"), "{error}");
        assert!(!error.contains("policy_server"), "{error}");
        assert!(!error.contains("webhooks"), "{error}");
    }
}
