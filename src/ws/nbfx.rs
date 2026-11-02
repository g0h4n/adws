//! MC-NBFX - .NET Binary XML, the on-wire form of the ADWS SOAP envelopes
//! (KnownEncoding 0x08 ⇒ NBFSE = NBFX + a string dictionary).
//!
//! Implemented: `MultiByteInt31`, the structural records (element/attribute/
//! xmlns/end), and the Chars/Bytes text records, with a Writer and a subset
//! Reader, round-trip tested. Record values are taken from \[MC-NBFX\] §2.2.3
//! (Bytes8Text=0x9E, Bytes16Text=0xA0 are spec-confirmed; the Chars block is
//! anchored to them). WithEndElement variants are the next odd value.
//!
//! NOT here yet: the **NBFSE string dictionary** (the static table + the
//! in-session dynamic dictionary) that maps dictionary ids ↔ the WS/AD
//! namespace and element strings. [`Dictionary`] abstracts it; populate it from
//! \[MC-NBFSE\] or go-adws next.

use std::collections::HashMap;

use crate::error::{AdwsError, Result};
use crate::ws::nbfs_dict::nbfs_static;

// Structural records (MC-NBFX 2.2.3).
pub const END_ELEMENT: u8 = 0x01;
pub const SHORT_ATTRIBUTE: u8 = 0x04;
pub const SHORT_DICT_ATTRIBUTE: u8 = 0x06;
pub const SHORT_XMLNS_ATTRIBUTE: u8 = 0x08;
pub const SHORT_DICT_XMLNS_ATTRIBUTE: u8 = 0x0A;
pub const SHORT_ELEMENT: u8 = 0x40;
pub const SHORT_DICT_ELEMENT: u8 = 0x42;

// Text records (even = standalone, +1 = WithEndElement).
pub const CHARS8: u8 = 0x98;
pub const CHARS16: u8 = 0x9A;
pub const CHARS32: u8 = 0x9C;
pub const BYTES8: u8 = 0x9E; // spec-confirmed
pub const BYTES16: u8 = 0xA0; // spec-confirmed
pub const BYTES32: u8 = 0xA2;

/// `MultiByteInt31`: 7 bits/byte, least significant group first, high bit =
/// continuation. Identical to the MC-NMF record-size encoding.
pub fn write_mbi31(out: &mut Vec<u8>, mut n: u32) {
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
}

/// Read a `MultiByteInt31`, returning `(value, bytes_consumed)`.
pub fn read_mbi31(buf: &[u8]) -> Result<(u32, usize)> {
    let mut value: u32 = 0;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate().take(5) {
        value |= ((b & 0x7f) as u32) << shift;
        if b & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(AdwsError::Xml("bad MultiByteInt31".into()))
}

/// Resolves NBFSE dictionary ids to/from strings. A real ADWS session needs the
/// MC-NBFSE static table plus the in-session dynamic entries.
pub trait Dictionary {
    fn id_of(&self, s: &str) -> Option<u32>;
    fn string_of(&self, id: u32) -> Option<&str>;
}

/// Empty dictionary: forces every name inline (no dictionary records). Correct
/// but larger on the wire; fine until the NBFSE table is ported.
pub struct NoDictionary;
impl Dictionary for NoDictionary {
    fn id_of(&self, _s: &str) -> Option<u32> {
        None
    }
    fn string_of(&self, _id: u32) -> Option<&str> {
        None
    }
}

fn write_inline_string(out: &mut Vec<u8>, s: &str) {
    write_mbi31(out, s.len() as u32);
    out.extend_from_slice(s.as_bytes());
}

fn write_text_record(out: &mut Vec<u8>, s: &str, with_end: bool) {
    let bytes = s.as_bytes();
    let (base, len_bytes): (u8, Vec<u8>) = if bytes.len() < 0x100 {
        (CHARS8, vec![bytes.len() as u8])
    } else if bytes.len() < 0x1_0000 {
        (CHARS16, (bytes.len() as u16).to_le_bytes().to_vec())
    } else {
        (CHARS32, (bytes.len() as u32).to_le_bytes().to_vec())
    };
    out.push(if with_end { base + 1 } else { base });
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(bytes);
}

fn write_bytes_record(out: &mut Vec<u8>, data: &[u8], with_end: bool) {
    let (base, len_bytes): (u8, Vec<u8>) = if data.len() < 0x100 {
        (BYTES8, vec![data.len() as u8])
    } else if data.len() < 0x1_0000 {
        (BYTES16, (data.len() as u16).to_le_bytes().to_vec())
    } else {
        (BYTES32, (data.len() as u32).to_le_bytes().to_vec())
    };
    out.push(if with_end { base + 1 } else { base });
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(data);
}

/// Writes an NBFX record stream. Names are emitted as dictionary records when
/// `dict` knows them, else inline.
pub struct Writer<'d, D: Dictionary> {
    out: Vec<u8>,
    dict: &'d D,
}

impl<'d, D: Dictionary> Writer<'d, D> {
    pub fn new(dict: &'d D) -> Self {
        Self { out: Vec::new(), dict }
    }

    pub fn start_element(&mut self, name: &str) {
        match self.dict.id_of(name) {
            Some(id) => {
                self.out.push(SHORT_DICT_ELEMENT);
                write_mbi31(&mut self.out, id);
            }
            None => {
                self.out.push(SHORT_ELEMENT);
                write_inline_string(&mut self.out, name);
            }
        }
    }

    /// An attribute is the attribute record + name, followed by a text record.
    pub fn attribute(&mut self, name: &str, value: &str) {
        self.out.push(SHORT_ATTRIBUTE);
        write_inline_string(&mut self.out, name);
        write_text_record(&mut self.out, value, false);
    }

    pub fn text(&mut self, s: &str) {
        write_text_record(&mut self.out, s, false);
    }

    pub fn base64(&mut self, data: &[u8]) {
        write_bytes_record(&mut self.out, data, false);
    }

    pub fn end_element(&mut self) {
        self.out.push(END_ELEMENT);
    }

    pub fn finish(self) -> Vec<u8> {
        self.out
    }
}

/// A decoded NBFX event (subset).
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    StartElement(String),
    /// A dictionary-id element whose string the caller resolves via the dictionary.
    StartDictElement(u32),
    Attribute { name: String, value: String },
    Text(String),
    Bytes(Vec<u8>),
    EndElement,
}

/// Parse the subset of records the Writer emits (inline + dictionary ids).
pub fn read_events(buf: &[u8]) -> Result<Vec<Event>> {
    let mut events = Vec::new();
    let mut i = 0usize;
    while i < buf.len() {
        let rec = buf[i];
        i += 1;
        match rec {
            END_ELEMENT => events.push(Event::EndElement),
            SHORT_ELEMENT => {
                let (s, used) = read_inline_string(&buf[i..])?;
                i += used;
                events.push(Event::StartElement(s));
            }
            SHORT_DICT_ELEMENT => {
                let (id, used) = read_mbi31(&buf[i..])?;
                i += used;
                events.push(Event::StartDictElement(id));
            }
            SHORT_ATTRIBUTE => {
                let (name, used) = read_inline_string(&buf[i..])?;
                i += used;
                let (value, used2) = read_text(&buf[i..])?;
                i += used2;
                events.push(Event::Attribute { name, value });
            }
            CHARS8 | CHARS16 | CHARS32 | 0x99 | 0x9B | 0x9D => {
                i -= 1;
                let (value, used) = read_text(&buf[i..])?;
                i += used;
                events.push(Event::Text(value));
                if rec & 1 == 1 {
                    events.push(Event::EndElement);
                }
            }
            BYTES8 | BYTES16 | BYTES32 | 0x9F | 0xA1 | 0xA3 => {
                i -= 1;
                let (data, used) = read_bytes(&buf[i..])?;
                i += used;
                events.push(Event::Bytes(data));
                if rec & 1 == 1 {
                    events.push(Event::EndElement);
                }
            }
            other => return Err(AdwsError::Xml(format!("unhandled NBFX record 0x{other:02X}"))),
        }
    }
    Ok(events)
}

fn read_inline_string(buf: &[u8]) -> Result<(String, usize)> {
    let (len, used) = read_mbi31(buf)?;
    let len = len as usize;
    let end = used + len;
    if buf.len() < end {
        return Err(AdwsError::Xml("truncated inline string".into()));
    }
    let s = String::from_utf8(buf[used..end].to_vec())
        .map_err(|e| AdwsError::Xml(format!("utf8: {e}")))?;
    Ok((s, end))
}

fn read_text(buf: &[u8]) -> Result<(String, usize)> {
    let rec = buf[0];
    let base = rec & !1;
    let (len, hdr) = match base {
        CHARS8 => (buf[1] as usize, 2),
        CHARS16 => (u16::from_le_bytes([buf[1], buf[2]]) as usize, 3),
        CHARS32 => (u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize, 5),
        other => return Err(AdwsError::Xml(format!("not a text record 0x{other:02X}"))),
    };
    let end = hdr + len;
    let s = String::from_utf8(buf[hdr..end].to_vec())
        .map_err(|e| AdwsError::Xml(format!("utf8: {e}")))?;
    Ok((s, end))
}

fn read_bytes(buf: &[u8]) -> Result<(Vec<u8>, usize)> {
    let rec = buf[0];
    let base = rec & !1;
    let (len, hdr) = match base {
        BYTES8 => (buf[1] as usize, 2),
        BYTES16 => (u16::from_le_bytes([buf[1], buf[2]]) as usize, 3),
        BYTES32 => (u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize, 5),
        other => return Err(AdwsError::Xml(format!("not a bytes record 0x{other:02X}"))),
    };
    let end = hdr + len;
    Ok((buf[hdr..end].to_vec(), end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mbi31_vectors() {
        let mut v = Vec::new();
        write_mbi31(&mut v, 300);
        assert_eq!(v, vec![0xAC, 0x02]);
        for n in [0u32, 5, 127, 128, 16_384, 2_097_152] {
            let mut b = Vec::new();
            write_mbi31(&mut b, n);
            assert_eq!(read_mbi31(&b).unwrap(), (n, b.len()));
        }
    }

    #[test]
    fn element_attr_text_roundtrip() {
        let dict = NoDictionary;
        let mut w = Writer::new(&dict);
        w.start_element("a");
        w.attribute("b", "x");
        w.text("hi");
        w.end_element();
        let bytes = w.finish();

        let events = read_events(&bytes).unwrap();
        assert_eq!(
            events,
            vec![
                Event::StartElement("a".into()),
                Event::Attribute { name: "b".into(), value: "x".into() },
                Event::Text("hi".into()),
                Event::EndElement,
            ]
        );
    }

    #[test]
    fn base64_record_roundtrip() {
        let dict = NoDictionary;
        let mut w = Writer::new(&dict);
        w.start_element("sid");
        w.base64(&[0x01, 0x05, 0x00, 0x00]);
        w.end_element();
        let events = read_events(&w.finish()).unwrap();
        assert_eq!(events[1], Event::Bytes(vec![0x01, 0x05, 0x00, 0x00]));
    }

    #[test]
    fn long_text_uses_chars16() {
        let dict = NoDictionary;
        let mut w = Writer::new(&dict);
        w.text(&"z".repeat(300));
        let bytes = w.finish();
        assert_eq!(bytes[0], CHARS16);
        let events = read_events(&bytes).unwrap();
        assert_eq!(events[0], Event::Text("z".repeat(300)));
    }
}

// ============================================================================
// NBFSE framing + response decoder (ported from go-adws transport/nbfse*.go)
// ============================================================================

/// MC-NBFSE session string table. Static (even) ids resolve against the NBFS
/// dictionary; dynamic (odd) ids are provided by each document's StringTable
/// prefix and persist across documents on one connection.
#[derive(Default)]
pub struct NbfseSession {
    dynamic: HashMap<u32, String>,
    next_odd: u32,
}

impl NbfseSession {
    pub fn new() -> Self {
        Self { dynamic: HashMap::new(), next_odd: 1 }
    }

    fn add_entries(&mut self, entries: Vec<String>) {
        for s in entries {
            self.dynamic.insert(self.next_odd, s);
            self.next_odd += 2;
        }
    }

    fn resolve(&self, id: u32) -> String {
        if id & 1 == 1 {
            self.dynamic
                .get(&id)
                .cloned()
                .unwrap_or_else(|| format!("value_{id:x}"))
        } else {
            nbfs_static(id)
                .map(str::to_string)
                .unwrap_or_else(|| format!("value_{id:x}"))
        }
    }
}

/// A decoded NBFX element tree.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NbfxNode {
    pub prefix: String,
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub text: String,
    pub children: Vec<NbfxNode>,
}

/// Prepend an empty StringTable (producer-side optimization off), as go-adws
/// does, to turn an NBFX record stream into an NBFSE payload for the wire.
pub fn encode_nbfse(nbfx_records: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + nbfx_records.len());
    out.push(0x00); // StringTable Size = 0
    out.extend_from_slice(nbfx_records);
    out
}

/// Decode an NBFSE payload (StringTable prefix + NBFX records) into a tree,
/// updating the session's dynamic string table.
pub fn decode_nbfse(session: &mut NbfseSession, payload: &[u8]) -> Result<NbfxNode> {
    if payload.is_empty() {
        return Err(AdwsError::Xml("empty NBFSE payload".into()));
    }
    let (size, used) = read_mbi31(payload)?;
    let mut off = used;
    let size = size as usize;
    if off + size > payload.len() {
        return Err(AdwsError::Xml("invalid StringTable size".into()));
    }
    if size > 0 {
        let mut entries = Vec::new();
        let table = &payload[off..off + size];
        let mut i = 0;
        while i < table.len() {
            let (s, u) = read_inline_string(&table[i..])?;
            entries.push(s);
            i += u;
        }
        session.add_entries(entries);
    }
    off += size;
    parse_records(&payload[off..], session)
}

/// Parse a bare NBFX record stream into a node tree.
pub fn parse_records(data: &[u8], session: &NbfseSession) -> Result<NbfxNode> {
    let mut root: Option<NbfxNode> = None;
    let mut stack: Vec<NbfxNode> = Vec::new();
    let mut off = 0usize;

    // Helper to attach a finished child to its parent (or set root).
    fn push_node(root: &mut Option<NbfxNode>, stack: &mut Vec<NbfxNode>, node: NbfxNode) {
        stack.push(node);
        let _ = root;
    }

    while off < data.len() {
        let t = data[off];
        off += 1;
        match t {
            END_ELEMENT => {
                if let Some(done) = stack.pop() {
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(done),
                        None => root = Some(done),
                    }
                }
            }
            0x40..=0x77 => {
                let (node, next) = decode_element_start(data, off, t, session)?;
                off = next;
                push_node(&mut root, &mut stack, node);
            }
            0x04..=0x3F => {
                let (name, prefix, value, next) = decode_attr(data, off, t, session)?;
                off = next;
                if let Some(cur) = stack.last_mut() {
                    let full = if prefix.is_empty() { name } else { format!("{prefix}:{name}") };
                    cur.attrs.push((full, value));
                } else {
                    return Err(AdwsError::Xml("attribute without active element".into()));
                }
            }
            _ => {
                // Text record: re-point at t.
                let (text, next, with_end) = decode_text(data, off - 1, session)?;
                off = next;
                if let Some(cur) = stack.last_mut() {
                    cur.text.push_str(&text);
                }
                if with_end {
                    if let Some(done) = stack.pop() {
                        match stack.last_mut() {
                            Some(parent) => parent.children.push(done),
                            None => root = Some(done),
                        }
                    }
                }
            }
        }
    }

    root.ok_or_else(|| AdwsError::Xml("no NBFX root element".into()))
}

fn decode_element_start(
    data: &[u8],
    off: usize,
    t: u8,
    session: &NbfseSession,
) -> Result<(NbfxNode, usize)> {
    let mut n = NbfxNode::default();
    match t {
        0x40 => {
            let (s, no) = read_inline_string(&data[off..])?;
            n.name = s;
            Ok((n, off + no))
        }
        0x41 => {
            let (p, no) = read_inline_string(&data[off..])?;
            let (s, no2) = read_inline_string(&data[off + no..])?;
            n.prefix = p;
            n.name = s;
            Ok((n, off + no + no2))
        }
        0x42 => {
            let (idx, nl) = read_mbi31(&data[off..])?;
            n.name = session.resolve(idx);
            Ok((n, off + nl))
        }
        0x43 => {
            let (p, no) = read_inline_string(&data[off..])?;
            let (idx, nl) = read_mbi31(&data[off + no..])?;
            n.prefix = p;
            n.name = session.resolve(idx);
            Ok((n, off + no + nl))
        }
        0x44..=0x5D => {
            let (idx, nl) = read_mbi31(&data[off..])?;
            n.prefix = ((b'a' + (t - 0x44)) as char).to_string();
            n.name = session.resolve(idx);
            Ok((n, off + nl))
        }
        0x5E..=0x77 => {
            let (s, no) = read_inline_string(&data[off..])?;
            n.prefix = ((b'a' + (t - 0x5E)) as char).to_string();
            n.name = s;
            Ok((n, off + no))
        }
        other => Err(AdwsError::Xml(format!("invalid element type 0x{other:02X}"))),
    }
}

/// Returns (name, prefix, value, next_off).
fn decode_attr(
    data: &[u8],
    off: usize,
    t: u8,
    session: &NbfseSession,
) -> Result<(String, String, String, usize)> {
    match t {
        0x08 => {
            let (v, no) = read_inline_string(&data[off..])?;
            Ok(("xmlns".into(), String::new(), v, off + no))
        }
        0x09 => {
            let (name, no) = read_inline_string(&data[off..])?;
            let (v, no2) = read_inline_string(&data[off + no..])?;
            Ok((name, "xmlns".into(), v, off + no + no2))
        }
        0x0A => {
            let (idx, nl) = read_mbi31(&data[off..])?;
            Ok(("xmlns".into(), String::new(), session.resolve(idx), off + nl))
        }
        0x0B => {
            let (name, no) = read_inline_string(&data[off..])?;
            let (idx, nl) = read_mbi31(&data[off + no..])?;
            Ok((name, "xmlns".into(), session.resolve(idx), off + no + nl))
        }
        0x04 => {
            let (name, no) = read_inline_string(&data[off..])?;
            let (v, nv) = decode_text_value(&data[off + no..], session)?;
            Ok((name, String::new(), v, off + no + nv))
        }
        0x05 => {
            let (prefix, no) = read_inline_string(&data[off..])?;
            let (name, no2) = read_inline_string(&data[off + no..])?;
            let (v, nv) = decode_text_value(&data[off + no + no2..], session)?;
            Ok((name, prefix, v, off + no + no2 + nv))
        }
        0x06 => {
            let (idx, nl) = read_mbi31(&data[off..])?;
            let (v, nv) = decode_text_value(&data[off + nl..], session)?;
            Ok((session.resolve(idx), String::new(), v, off + nl + nv))
        }
        0x07 => {
            let (prefix, no) = read_inline_string(&data[off..])?;
            let (idx, nl) = read_mbi31(&data[off + no..])?;
            let (v, nv) = decode_text_value(&data[off + no + nl..], session)?;
            Ok((session.resolve(idx), prefix, v, off + no + nl + nv))
        }
        0x0C..=0x25 => {
            let prefix = ((b'a' + (t - 0x0C)) as char).to_string();
            let (idx, nl) = read_mbi31(&data[off..])?;
            let (v, nv) = decode_text_value(&data[off + nl..], session)?;
            Ok((session.resolve(idx), prefix, v, off + nl + nv))
        }
        0x26..=0x3F => {
            let prefix = ((b'a' + (t - 0x26)) as char).to_string();
            let (name, no) = read_inline_string(&data[off..])?;
            let (v, nv) = decode_text_value(&data[off + no..], session)?;
            Ok((name, prefix, v, off + no + nv))
        }
        other => Err(AdwsError::Xml(format!("unsupported attribute type 0x{other:02X}"))),
    }
}

fn decode_text_value(data: &[u8], session: &NbfseSession) -> Result<(String, usize)> {
    // Attribute values never carry WithEndElement.
    let (v, next, _we) = decode_text(data, 0, session)?;
    Ok((v, next))
}

/// Decode one text record starting at `data[off]`. Returns (value, new_off,
/// with_end_element). Ported from go-adws decodeText (common subset).
fn decode_text(data: &[u8], off: usize, session: &NbfseSession) -> Result<(String, usize, bool)> {
    if off >= data.len() {
        return Err(AdwsError::Xml("unexpected end in text".into()));
    }
    let raw = data[off];
    let with_end = raw & 1 == 1;
    let t = if with_end { raw - 1 } else { raw };
    let mut p = off + 1;

    let value = match t {
        0x80 => "0".to_string(),
        0x82 => "1".to_string(),
        0x84 => "false".to_string(),
        0x86 => "true".to_string(),
        0x88 => {
            let v = data[p] as i8;
            p += 1;
            v.to_string()
        }
        0x8A => {
            let v = i16::from_le_bytes([data[p], data[p + 1]]);
            p += 2;
            v.to_string()
        }
        0x8C => {
            let v = i32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
            p += 4;
            v.to_string()
        }
        0x8E => {
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[p..p + 8]);
            p += 8;
            i64::from_le_bytes(b).to_string()
        }
        0x90 => {
            let v = f32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
            p += 4;
            format!("{v}")
        }
        0x92 => {
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[p..p + 8]);
            p += 8;
            format!("{}", f64::from_le_bytes(b))
        }
        0x98 | 0x9A | 0x9C => {
            let (len, hdr) = text_len(data, p, t)?;
            p += hdr;
            let s = String::from_utf8(data[p..p + len].to_vec())
                .map_err(|e| AdwsError::Xml(format!("utf8: {e}")))?;
            p += len;
            s
        }
        0x9E | 0xA0 | 0xA2 => {
            let (len, hdr) = bytes_len(data, p, t)?;
            p += hdr;
            use base64::Engine;
            let s = base64::engine::general_purpose::STANDARD.encode(&data[p..p + len]);
            p += len;
            s
        }
        0xA8 => String::new(),
        0xAA => {
            let (idx, nl) = read_mbi31(&data[p..])?;
            p += nl;
            session.resolve(idx)
        }
        0xAC => {
            let g = format_guid_le(&data[p..p + 16]);
            p += 16;
            format!("urn:uuid:{g}")
        }
        0xB0 => {
            let g = format_guid_le(&data[p..p + 16]);
            p += 16;
            g
        }
        0xB2 => {
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[p..p + 8]);
            p += 8;
            u64::from_le_bytes(b).to_string()
        }
        0xB4 => {
            let v = if data[p] == 0 { "false" } else { "true" };
            p += 1;
            v.to_string()
        }
        // UnicodeChars8/16/32Text: UTF-16LE string, byte-length prefix 1/2/4.
        0xB6 | 0xB8 | 0xBA => {
            let (len, hdr) = match t {
                0xB6 => (data[p] as usize, 1),
                0xB8 => (u16::from_le_bytes([data[p], data[p + 1]]) as usize, 2),
                _ => (u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]) as usize, 4),
            };
            p += hdr;
            let units: Vec<u16> = data[p..p + len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let s = String::from_utf16(&units)
                .map_err(|e| AdwsError::Xml(format!("utf16: {e}")))?;
            p += len;
            s
        }
        other => {
            return Err(AdwsError::Xml(format!("unsupported text record 0x{other:02X}")))
        }
    };
    Ok((value, p, with_end))
}

fn text_len(data: &[u8], p: usize, base: u8) -> Result<(usize, usize)> {
    Ok(match base {
        0x98 => (data[p] as usize, 1),
        0x9A => (u16::from_le_bytes([data[p], data[p + 1]]) as usize, 2),
        0x9C => (u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]) as usize, 4),
        _ => return Err(AdwsError::Xml("bad chars record".into())),
    })
}

fn bytes_len(data: &[u8], p: usize, base: u8) -> Result<(usize, usize)> {
    Ok(match base {
        0x9E => (data[p] as usize, 1),
        0xA0 => (u16::from_le_bytes([data[p], data[p + 1]]) as usize, 2),
        0xA2 => (u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]) as usize, 4),
        _ => return Err(AdwsError::Xml("bad bytes record".into())),
    })
}

/// .NET GUID little-endian layout => canonical string.
fn format_guid_le(b: &[u8]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

#[cfg(test)]
mod nbfse_tests {
    use super::*;

    #[test]
    fn static_dict_resolves() {
        assert_eq!(nbfs_static(2), Some("Envelope"));
        assert_eq!(nbfs_static(4), Some("http://www.w3.org/2003/05/soap-envelope"));
    }

    #[test]
    fn nbfse_roundtrip_tree() {
        let dict = NoDictionary;
        let mut w = Writer::new(&dict);
        w.start_element("a");
        w.start_element("b");
        w.text("hi");
        w.end_element();
        w.end_element();
        let payload = encode_nbfse(&w.finish());

        let mut sess = NbfseSession::new();
        let root = decode_nbfse(&mut sess, &payload).unwrap();
        assert_eq!(root.name, "a");
        assert_eq!(root.children.len(), 1);
        assert_eq!(root.children[0].name, "b");
        assert_eq!(root.children[0].text, "hi");
    }

    #[test]
    fn dict_element_resolves_from_static() {
        // StringTable size 0, ShortDictElement(0x42) id=2 ("Envelope"), EndElement.
        let payload = [0x00u8, 0x42, 0x02, 0x01];
        let mut sess = NbfseSession::new();
        let root = decode_nbfse(&mut sess, &payload).unwrap();
        assert_eq!(root.name, "Envelope");
    }
}

// ============================================================================
// Request encoder: text SOAP (XML) -> inline NBFX -> NBFSE payload.
// The static dictionary is only an optimization, so we emit every name inline;
// a conformant DC decodes inline records fine.
// ============================================================================

use quick_xml::events::Event as XmlEvent;
use quick_xml::reader::Reader;

fn write_element_start(out: &mut Vec<u8>, qname: &str) {
    match qname.split_once(':') {
        Some((prefix, local)) => {
            out.push(0x41); // Element: prefix + name
            write_inline_string(out, prefix);
            write_inline_string(out, local);
        }
        None => {
            out.push(SHORT_ELEMENT);
            write_inline_string(out, qname);
        }
    }
}

fn write_attribute(out: &mut Vec<u8>, key: &str, value: &str) {
    if key == "xmlns" {
        out.push(SHORT_XMLNS_ATTRIBUTE); // 0x08
        write_inline_string(out, value);
        return;
    }
    if let Some(prefix_name) = key.strip_prefix("xmlns:") {
        out.push(0x09); // XmlnsAttribute: xmlns:<name>
        write_inline_string(out, prefix_name);
        write_inline_string(out, value);
        return;
    }
    match key.split_once(':') {
        Some((prefix, local)) => {
            out.push(0x05); // Attribute: prefix + name
            write_inline_string(out, prefix);
            write_inline_string(out, local);
        }
        None => {
            out.push(SHORT_ATTRIBUTE); // 0x04
            write_inline_string(out, key);
        }
    }
    write_text_record(out, value, false);
}

fn encode_start(out: &mut Vec<u8>, e: &quick_xml::events::BytesStart) -> Result<()> {
    let qname = std::str::from_utf8(e.name().as_ref())
        .map_err(|err| AdwsError::Xml(format!("element name: {err}")))?
        .to_string();
    write_element_start(out, &qname);
    for a in e.attributes() {
        let a = a.map_err(|err| AdwsError::Xml(format!("attribute: {err}")))?;
        let key = std::str::from_utf8(a.key.as_ref())
            .map_err(|err| AdwsError::Xml(format!("attr key: {err}")))?
            .to_string();
        let val = a
            .unescape_value()
            .map_err(|err| AdwsError::Xml(format!("attr value: {err}")))?
            .into_owned();
        write_attribute(out, &key, &val);
    }
    Ok(())
}

/// Encode a SOAP XML string into an inline NBFX record stream.
pub fn encode_xml(xml: &str) -> Result<Vec<u8>> {
    let mut reader = Reader::from_str(xml);
    let mut out = Vec::new();

    loop {
        match reader.read_event() {
            Ok(XmlEvent::Decl(_)) | Ok(XmlEvent::Comment(_)) | Ok(XmlEvent::PI(_)) | Ok(XmlEvent::DocType(_)) => {}
            Ok(XmlEvent::Start(e)) => encode_start(&mut out, &e)?,
            Ok(XmlEvent::Empty(e)) => {
                encode_start(&mut out, &e)?;
                out.push(END_ELEMENT);
            }
            Ok(XmlEvent::Text(e)) => {
                let t = e
                    .unescape()
                    .map_err(|err| AdwsError::Xml(format!("text: {err}")))?
                    .into_owned();
                if !t.trim().is_empty() {
                    write_text_record(&mut out, &t, false);
                }
            }
            Ok(XmlEvent::End(_)) => out.push(END_ELEMENT),
            Ok(XmlEvent::Eof) => break,
            Ok(XmlEvent::CData(_)) => {}
            Err(e) => return Err(AdwsError::Xml(format!("xml parse: {e}"))),
        }
    }
    Ok(out)
}

/// Encode a SOAP XML string into a full NBFSE payload ready for the NNS channel.
pub fn encode_nbfse_request(xml: &str) -> Result<Vec<u8>> {
    Ok(encode_nbfse(&encode_xml(xml)?))
}

#[cfg(test)]
mod request_tests {
    use super::*;

    #[test]
    fn xml_request_roundtrips_through_codec() {
        let xml = r#"<s:Envelope xmlns:s="http://soap"><s:Body><wsen:Enumerate xmlns:wsen="http://enum"><wsen:Filter>(objectClass=user)</wsen:Filter></wsen:Enumerate></s:Body></s:Envelope>"#;
        let payload = encode_nbfse_request(xml).unwrap();

        let mut sess = NbfseSession::new();
        let root = decode_nbfse(&mut sess, &payload).unwrap();
        assert_eq!(root.name, "Envelope");
        assert_eq!(root.prefix, "s");

        fn find<'a>(n: &'a NbfxNode, name: &str) -> Option<&'a NbfxNode> {
            if n.name == name {
                return Some(n);
            }
            n.children.iter().find_map(|c| find(c, name))
        }
        let filter = find(&root, "Filter").expect("Filter element");
        assert_eq!(filter.text, "(objectClass=user)");
    }
}
