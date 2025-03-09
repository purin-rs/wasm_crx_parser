use byteorder::{LittleEndian, ReadBytesExt};
use js_sys::Uint8Array;
use std::io::{Cursor, Read};
use wasm_bindgen::prelude::*;

// Initialize panic hook for better error messages
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub struct CrxInfo {
    version: u32,
    public_key: Vec<u8>,
    signature: Vec<u8>,
    zip_offset: usize,
}

#[wasm_bindgen]
impl CrxInfo {
    #[wasm_bindgen(getter)]
    pub fn version(&self) -> u32 {
        self.version
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Uint8Array {
        Uint8Array::from(&self.public_key[..])
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Uint8Array {
        Uint8Array::from(&self.signature[..])
    }

    #[wasm_bindgen(getter)]
    pub fn zip_offset(&self) -> usize {
        self.zip_offset
    }
}

#[wasm_bindgen]
pub fn parse_crx(data: &[u8]) -> Result<CrxInfo, JsValue> {
    let mut cursor = Cursor::new(data);

    // Read magic number ("Cr24")
    let mut magic = [0u8; 4];
    cursor
        .read_exact(&mut magic)
        .map_err(|e| JsValue::from_str(&format!("Failed to read magic number: {}", e)))?;

    if &magic != b"Cr24" {
        return Err(JsValue::from_str(
            "Invalid CRX file: incorrect magic number",
        ));
    }

    // Read version
    let version = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| JsValue::from_str(&format!("Failed to read version: {}", e)))?;

    // Sanity check for header size based on version
    let total_size = cursor.get_ref().len();
    let min_header_size = match version {
        2 => 16, // Magic(4) + Version(4) + PubKeyLen(4) + SigLen(4) + minimal data
        3 => 12, // Magic(4) + Version(4) + HeaderSize(4) + minimal protobuf header
        _ => {
            return Err(JsValue::from_str(&format!(
                "Unsupported CRX version: {}",
                version
            )));
        }
    };

    if total_size < min_header_size {
        return Err(JsValue::from_str(&format!(
            "CRX file too small for version {}: size {} bytes, expected at least {} bytes",
            version, total_size, min_header_size
        )));
    }

    // Version-specific parsing
    let info = match version {
        2 => parse_crx2(&mut cursor)?,
        3 => parse_crx3(&mut cursor)?,
        _ => {
            return Err(JsValue::from_str(&format!(
                "Unsupported CRX version: {}",
                version
            )));
        }
    };

    //verify the structure
    verify_crx_info(&info)?;

    Ok(info)
}

fn parse_crx2(cursor: &mut Cursor<&[u8]>) -> Result<CrxInfo, JsValue> {
    // Read public key length
    let pub_key_len = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| JsValue::from_str(&format!("Failed to read public key length: {}", e)))?
        as usize;

    // Read signature length
    let sig_len = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| JsValue::from_str(&format!("Failed to read signature length: {}", e)))?
        as usize;

    // Read public key
    let mut public_key = vec![0u8; pub_key_len];
    cursor
        .read_exact(&mut public_key)
        .map_err(|e| JsValue::from_str(&format!("Failed to read public key: {}", e)))?;

    // Read signature
    let mut signature = vec![0u8; sig_len];
    cursor
        .read_exact(&mut signature)
        .map_err(|e| JsValue::from_str(&format!("Failed to read signature: {}", e)))?;

    // Calculate ZIP offset
    let zip_offset = 4 + 4 + 4 + 4 + pub_key_len + sig_len; // Magic + Version + PubKeyLen + SigLen + PubKey + Sig

    // Optional verification of ZIP signature
    cursor.set_position(zip_offset as u64);
    let mut zip_signature = [0u8; 4];
    if cursor
        .read(&mut zip_signature)
        .map_err(|e| JsValue::from_str(&format!("Failed to read ZIP signature: {}", e)))?
        == 4
    {
        if zip_signature[0] != 0x50 || zip_signature[1] != 0x4B {
            return Err(JsValue::from_str(
                "Invalid ZIP data in CRX file (PK signature missing)",
            ));
        }
    }

    Ok(CrxInfo {
        version: 2,
        public_key,
        signature,
        zip_offset,
    })
}

// Improved Rust code for parsing CRX3
fn parse_crx3(cursor: &mut Cursor<&[u8]>) -> Result<CrxInfo, JsValue> {
    cursor.set_position(8); // Already read magic number and version

    // Read header size (4 bytes)
    let mut header_size_bytes = [0u8; 4];
    cursor
        .read_exact(&mut header_size_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to read header size: {}", e)))?;
    let header_size = u32::from_le_bytes(header_size_bytes) as usize;

    // Read header data
    let mut header_data = vec![0u8; header_size];
    cursor
        .read_exact(&mut header_data)
        .map_err(|e| JsValue::from_str(&format!("Failed to read header data: {}", e)))?;

    // Calculate ZIP offset
    let zip_offset = 12 + header_size; // 4 bytes magic + 4 bytes version + 4 bytes header size + header data
    // Here we might parse the protobuf header to extract public key and signature
    // For simplicity, we'll use empty values if you don't need these fields
    let public_key = Vec::new();
    let signature = Vec::new();

    // Optional: Verify ZIP signature
    let current_position = cursor.position() as usize;
    if current_position != zip_offset {
        cursor.set_position(zip_offset as u64);
    }

    let mut zip_signature = [0u8; 4];
    if cursor
        .read(&mut zip_signature)
        .map_err(|e| JsValue::from_str(&format!("Failed to read ZIP signature: {}", e)))?
        == 4
    {
        if zip_signature[0] != 0x50 || zip_signature[1] != 0x4B {
            return Err(JsValue::from_str(
                "Invalid ZIP data in CRX file (PK signature missing)",
            ));
        }
    }

    Ok(CrxInfo {
        version: 3,
        public_key,
        signature,
        zip_offset,
    })
}

#[wasm_bindgen]
pub fn extract_zip_data(data: &[u8]) -> Result<Uint8Array, JsValue> {
    let crx_info = parse_crx(data)?;

    // Extract the ZIP portion of the file starting at the calculated offset
    let zip_data = &data[crx_info.zip_offset..];
    Ok(Uint8Array::from(zip_data))
}

fn verify_crx_info(info: &CrxInfo) -> Result<(), JsValue> {
    // For CRX2 files, we expect non-empty public key and signature
    if info.version == 2 {
        if info.public_key.is_empty() {
            return Err(JsValue::from_str(
                "Invalid CRX2 structure: Public key is empty",
            ));
        }
        if info.signature.is_empty() {
            return Err(JsValue::from_str(
                "Invalid CRX2 structure: Signature is empty",
            ));
        }
    }
    // For CRX3 files, we expect empty public_key and signature in our struct
    // as they're stored differently in the protobuf header
    else if info.version == 3 {
        if !info.public_key.is_empty() {
            return Err(JsValue::from_str(
                "Invalid CRX3 structure: Public key should be empty",
            ));
        }
        if !info.signature.is_empty() {
            return Err(JsValue::from_str(
                "Invalid CRX3 structure: Signature should be empty",
            ));
        }
    }

    // Verify the zip_offset is reasonable (greater than minimum header size)
    let min_offset = if info.version == 2 { 16 } else { 12 };
    if info.zip_offset < min_offset {
        return Err(JsValue::from_str(&format!(
            "Invalid zip offset: {} (should be at least {})",
            info.zip_offset, min_offset
        )));
    }

    Ok(())
}
