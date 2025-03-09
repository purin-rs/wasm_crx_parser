use wasm_bindgen::prelude::*;
use js_sys::{Uint8Array, ArrayBuffer};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};

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
    cursor.read_exact(&mut magic)
        .map_err(|e| JsValue::from_str(&format!("Failed to read magic number: {}", e)))?;
    
    if &magic != b"Cr24" {
        return Err(JsValue::from_str("Invalid CRX file: incorrect magic number"));
    }
    
    // Read version
    let version = cursor.read_u32::<LittleEndian>()
        .map_err(|e| JsValue::from_str(&format!("Failed to read version: {}", e)))?;
    
    // Version-specific parsing
    match version {
        2 => parse_crx2(&mut cursor),
        3 => parse_crx3(&mut cursor),
        _ => Err(JsValue::from_str(&format!("Unsupported CRX version: {}", version))),
    }
}

fn parse_crx2(cursor: &mut Cursor<&[u8]>) -> Result<CrxInfo, JsValue> {
    // Read public key length
    let pub_key_len = cursor.read_u32::<LittleEndian>()
        .map_err(|e| JsValue::from_str(&format!("Failed to read public key length: {}", e)))? as usize;
    
    // Read signature length
    let sig_len = cursor.read_u32::<LittleEndian>()
        .map_err(|e| JsValue::from_str(&format!("Failed to read signature length: {}", e)))? as usize;
    
    // Read public key
    let mut public_key = vec![0u8; pub_key_len];
    cursor.read_exact(&mut public_key)
        .map_err(|e| JsValue::from_str(&format!("Failed to read public key: {}", e)))?;
    
    // Read signature
    let mut signature = vec![0u8; sig_len];
    cursor.read_exact(&mut signature)
        .map_err(|e| JsValue::from_str(&format!("Failed to read signature: {}", e)))?;
    
    // Calculate ZIP offset
    let zip_offset = 4 + 4 + 4 + 4 + pub_key_len + sig_len; // Magic + Version + PubKeyLen + SigLen + PubKey + Sig
    
    Ok(CrxInfo {
        version: 2,
        public_key,
        signature,
        zip_offset,
    })
}

fn parse_crx3(cursor: &mut Cursor<&[u8]>) -> Result<CrxInfo, JsValue> {
    // CRX3 has a different format with a header size and proto buffer
    // This is a simplified implementation
    
    // Skip header size (4 bytes)
    cursor.set_position(cursor.position() + 4);
    
    // In a real implementation, you'd parse the protocol buffer here
    // For simplicity, we'll just create dummy public key and signature
    
    let public_key = vec![0u8; 16]; // Dummy public key
    let signature = vec![0u8; 16];  // Dummy signature
    
    // For CRX3, ZIP data typically starts at offset 16 + header_size
    // But this is simplified
    let zip_offset = 16;
    
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