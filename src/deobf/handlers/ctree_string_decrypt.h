#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Ctree String Decryption Handler
//
// Analyzes the decompiled ctree to detect and resolve string obfuscation
// patterns that are easier to identify at the high-level IR than at
// microcode level.
//
// Detected patterns:
//
// 1. strcpy/memcpy reveals:
//    strcpy(decrypted_buffer, "plaintext_value");
//    memcpy(buffer, "AES_KEY_HERE", 16);
//    -> The destination variable gets associated with the plaintext
//
// 2. Character-by-character construction:
//    buffer[0] = 'h'; buffer[1] = 'e'; buffer[2] = 'l'; ...
//    buffer[0] = 104; buffer[1] = 101; buffer[2] = 108; ...
//    -> Reconstructs the string from individual assignments
//
// 3. XOR decryption loops:
//    for (i = 0; i < len; i++) dest[i] = src[i] ^ key[i];
//    -> Identifies XOR operations and extracts key if constant
//
// 4. AES/Crypto parameter detection:
//    CCCrypt(kCCDecrypt, kCCAlgorithmAES, ..., key, 16, iv, ...);
//    -> Extracts encryption keys and IVs from crypto calls
//
// 5. String transformation chains:
//    base64_decode(encrypted, decoded);
//    aes_decrypt(decoded, plaintext);
//    -> Tracks data flow through transformation functions
//
// Output:
//   - Annotates decompiled code with decrypted strings
//   - Populates ctx->decrypted_strings for other handlers
//   - Can modify ctree to replace encrypted refs with constants
//--------------------------------------------------------------------------

#include <set>
#include <map>

class ctree_string_decrypt_handler_t {
public:
    // Main entry point - run on decompiled function
    static int run(cfunc_t *cfunc, deobf_ctx_t *ctx);
    
    // Detection - check if function likely has string obfuscation
    static bool detect(cfunc_t *cfunc);

    //----------------------------------------------------------------------
    // Public types (used by visitor classes in .cpp)
    //----------------------------------------------------------------------
    
    // Info about a revealed string
    struct string_reveal_t {
        ea_t location;              // Where in the code
        qstring dest_name;          // Destination variable name
        ea_t dest_addr;             // Destination address (if global)
        qstring plaintext;          // The revealed plaintext
        int reveal_type;            // 0=strcpy, 1=memcpy, 2=assignment
    };
    
    // Find strcpy(dest, "plaintext") patterns
    static std::vector<string_reveal_t> find_strcpy_reveals(cfunc_t *cfunc);
    
    // Find memcpy(dest, "plaintext", size) patterns
    static std::vector<string_reveal_t> find_memcpy_reveals(cfunc_t *cfunc);
    
    //----------------------------------------------------------------------
    // Character-by-character string detection
    //----------------------------------------------------------------------
    
    // Info about a constructed string
    struct char_string_t {
        ea_t start_addr;            // First assignment address
        qstring var_name;           // Variable being assigned to
        ea_t var_addr;              // Global address if applicable
        qstring reconstructed;      // The reconstructed string
        std::vector<ea_t> insn_addrs;  // All assignment addresses
        bool uses_transform;        // XOR/NOT used in assignments
    };
    
    // Find buffer[i] = char patterns and reconstruct strings
    static std::vector<char_string_t> find_char_assignments(cfunc_t *cfunc);
    
    //----------------------------------------------------------------------
    // XOR decryption detection
    //----------------------------------------------------------------------
    
    // Info about an XOR decryption pattern
    struct xor_decrypt_t {
        ea_t location;              // Location of XOR operation
        ea_t encrypted_addr;        // Address of encrypted data
        qstring encrypted_name;     // Name of encrypted variable
        std::vector<uint8_t> xor_keys;  // Extracted XOR keys
        qstring decrypted;          // Decrypted result
    };
    
    // Find XOR operations with constant keys
    static std::vector<xor_decrypt_t> find_xor_patterns(cfunc_t *cfunc);
    
    //----------------------------------------------------------------------
    // Crypto function detection
    //----------------------------------------------------------------------
    
    // Info about a crypto call
    struct crypto_call_t {
        ea_t location;              // Call location
        qstring function;           // "CCCrypt", "AES_decrypt", etc.
        int algorithm;              // 0=AES-128, 1=AES-256, etc.
        std::vector<uint8_t> key;   // Extracted key
        std::vector<uint8_t> iv;    // Extracted IV
        ea_t input_addr;            // Input buffer address
        size_t input_len;           // Input buffer length
        ea_t output_addr;           // Output buffer address
        qstring decrypted;          // Decrypted plaintext (if successful)
    };
    
    // Find crypto function calls and extract parameters
    static std::vector<crypto_call_t> find_crypto_calls(cfunc_t *cfunc);

private:
    //----------------------------------------------------------------------
    // Annotation and patching
    //----------------------------------------------------------------------
    
    // Add comment with decrypted string
    static void annotate_reveal(const string_reveal_t &reveal);
    static void annotate_char_string(const char_string_t &str);
    static void annotate_xor_decrypt(const xor_decrypt_t &xor_info);
    static void annotate_crypto_call(const crypto_call_t &crypto);
    
    // Replace encrypted reference with decrypted constant in ctree
    static int patch_ctree_reference(cfunc_t *cfunc, ea_t encrypted_addr, 
                                     const qstring &decrypted);
    
    // Replace all encrypted strings in ctree using known plaintexts
    static int replace_encrypted_strings(cfunc_t *cfunc,
                                        const std::map<ea_t, qstring> &known_plaintexts);
    
    //----------------------------------------------------------------------
    // Helper functions
    //----------------------------------------------------------------------
    
    // Extract string constant from expression
    static bool get_string_constant(const cexpr_t *e, qstring *out);
    
    // Get variable/global address from expression
    static ea_t get_address_from_expr(const cexpr_t *e, cfunc_t *cfunc);
    
    // Check if expression is a known string function
    static bool is_string_function(const cexpr_t *e, qstring *func_name);
    
    // Check if expression is a known crypto function
    static bool is_crypto_function(const cexpr_t *e, qstring *func_name);
    
    // Try to extract constant value from expression
    static bool get_const_value(const cexpr_t *e, uint64_t *out);
    
    // Try to resolve a buffer's contents from initializers
    static bool get_buffer_contents(ea_t addr, size_t max_len, 
                                    std::vector<uint8_t> *out);
};
