// index.js
import initWasm, * as wasm from "../pkg/wasm_crx_parser.js";

// Track initialization state
let initialized = false;
let initPromise = null;

export class CrxParser {
  /**
   * Initialize the WebAssembly module
   * @returns {Promise<void>}
   */
  static async initialize() {
    // Use the correct initialization function name (initWasm)
    await initWasm();
  }


  /**
   * Parse a CRX file
   * @param {ArrayBuffer} buffer - The CRX file as an ArrayBuffer
   * @returns {Object} Parsed CRX information
   */
  static async parse(buffer) {
    // Ensure initialization before using any wasm functions
    await this.initialize();

    const bytes = new Uint8Array(buffer);
    const crxInfo = wasm.parse_crx(bytes);

    return {
      version: crxInfo.version,
      publicKey: new Uint8Array(crxInfo.public_key),
      signature: new Uint8Array(crxInfo.signature),
      zipOffset: crxInfo.zip_offset
    };
  }

  /**
   * Extract the ZIP content from a CRX file
   * @param {ArrayBuffer} buffer - The CRX file as an ArrayBuffer
   * @returns {Uint8Array} The ZIP content as a Uint8Array
   */
  static extractZip(buffer) {
    const bytes = new Uint8Array(buffer);
    let zipData;

    try {
      // Extract using the WebAssembly function
      zipData = wasm.extract_zip_data(bytes);

      // Validate ZIP header (PK signature)
      if (!(zipData[0] === 0x50 && zipData[1] === 0x4B)) {
        console.error("Invalid ZIP header - missing PK signature");
        throw new Error("Extracted data is not a valid ZIP file (missing signature)");
      }

      // Log ZIP header information for debugging
      console.log("ZIP header bytes:", Array.from(zipData.slice(0, 20)).map(b => b.toString(16).padStart(2, '0')).join(' '));

      return zipData;
    } catch (error) {
      console.error("ZIP extraction error:", error);
      throw error;
    }
  }



  /**
   * Manual fallback method to extract ZIP data from a CRX file
   * @param {Uint8Array} bytes - The CRX file as a Uint8Array
   * @returns {Uint8Array} The ZIP content as a Uint8Array
   */
  static manualExtractZip(bytes) {
    try {
      // Parse the CRX to get the zip offset
      const crxInfo = wasm.parse_crx(bytes);
      const zipOffset = crxInfo.zip_offset; // Access as property, not method

      console.log(`Manual extraction: ZIP data starts at offset ${zipOffset}`);

      // Extract ZIP data starting from the offset
      return bytes.slice(zipOffset);
    } catch (error) {
      console.error("Error in manual ZIP extraction:", error);
      throw new Error("Failed to extract ZIP data: " + error.message);
    }
  }

}