#include "ctree_string_decrypt.h"
#include "../analysis/pattern_match.h"

//--------------------------------------------------------------------------
// Platform-specific crypto support
//--------------------------------------------------------------------------
#ifdef __APPLE__
#include <CommonCrypto/CommonCrypto.h>
#define HAS_COMMONCRYPTO 1
#else
#define HAS_COMMONCRYPTO 0
#endif

//--------------------------------------------------------------------------
// Debug logging
//--------------------------------------------------------------------------
#include <fcntl.h>
#include <unistd.h>

static void ctree_str_debug(const char *fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    int len = qvsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    int fd = open("/tmp/ctree_string_debug.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        write(fd, buf, len);
        close(fd);
    }
}

//--------------------------------------------------------------------------
// AES Decryption Support
//--------------------------------------------------------------------------
#if HAS_COMMONCRYPTO

// AES-CBC decryption using CommonCrypto
// Returns decrypted data, empty on failure
static std::vector<uint8_t> aes_decrypt_cbc(
    const std::vector<uint8_t> &ciphertext,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    bool pkcs7_padding = true)
{
    std::vector<uint8_t> plaintext;
    
    if (ciphertext.empty() || key.empty())
        return plaintext;
    
    // Validate key size (16=AES-128, 24=AES-192, 32=AES-256)
    size_t key_size = key.size();
    if (key_size != kCCKeySizeAES128 && 
        key_size != kCCKeySizeAES192 && 
        key_size != kCCKeySizeAES256) {
        ctree_str_debug("[aes] Invalid key size: %zu\n", key_size);
        return plaintext;
    }
    
    // IV must be 16 bytes for AES-CBC
    if (!iv.empty() && iv.size() != kCCBlockSizeAES128) {
        ctree_str_debug("[aes] Invalid IV size: %zu (expected 16)\n", iv.size());
        return plaintext;
    }
    
    // Allocate output buffer (same size as input + block for padding)
    size_t out_size = ciphertext.size() + kCCBlockSizeAES128;
    plaintext.resize(out_size);
    size_t decrypted_size = 0;
    
    CCCryptorStatus status = CCCrypt(
        kCCDecrypt,
        kCCAlgorithmAES,
        pkcs7_padding ? kCCOptionPKCS7Padding : 0,
        key.data(), key_size,
        iv.empty() ? nullptr : iv.data(),
        ciphertext.data(), ciphertext.size(),
        plaintext.data(), out_size,
        &decrypted_size
    );
    
    if (status != kCCSuccess) {
        ctree_str_debug("[aes] Decryption failed with status: %d\n", status);
        plaintext.clear();
        return plaintext;
    }
    
    plaintext.resize(decrypted_size);
    ctree_str_debug("[aes] Decrypted %zu bytes successfully\n", decrypted_size);
    return plaintext;
}

// Try to decrypt data at an address using extracted key/IV
static bool try_aes_decrypt_at_address(
    ea_t data_addr,
    size_t data_len,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    qstring *out_plaintext)
{
    if (data_addr == BADADDR || data_len == 0 || !out_plaintext)
        return false;
    
    // Read encrypted data from binary
    std::vector<uint8_t> ciphertext(data_len);
    if (get_bytes(ciphertext.data(), data_len, data_addr) != data_len) {
        ctree_str_debug("[aes] Failed to read %zu bytes from 0x%llx\n", 
                       data_len, (unsigned long long)data_addr);
        return false;
    }
    
    // Try decryption
    std::vector<uint8_t> plaintext = aes_decrypt_cbc(ciphertext, key, iv, true);
    if (plaintext.empty())
        return false;
    
    // Check if result looks like valid text
    bool is_printable = true;
    for (size_t i = 0; i < plaintext.size() && i < 256; i++) {
        uint8_t c = plaintext[i];
        if (c == 0) break;  // Null terminator is ok
        if (c < 0x20 || c > 0x7E) {
            if (c != '\n' && c != '\r' && c != '\t') {
                is_printable = false;
                break;
            }
        }
    }
    
    if (is_printable && !plaintext.empty()) {
        // Find null terminator or end
        size_t str_len = 0;
        for (size_t i = 0; i < plaintext.size(); i++) {
            if (plaintext[i] == 0) break;
            str_len++;
        }
        out_plaintext->append((const char*)plaintext.data(), str_len);
        return true;
    }
    
    return false;
}

#else
// No CommonCrypto - stub implementations
static std::vector<uint8_t> aes_decrypt_cbc(
    const std::vector<uint8_t> &ciphertext,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    bool pkcs7_padding = true)
{
    ctree_str_debug("[aes] CommonCrypto not available on this platform\n");
    return {};
}

static bool try_aes_decrypt_at_address(
    ea_t data_addr,
    size_t data_len,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    qstring *out_plaintext)
{
    return false;
}
#endif

//--------------------------------------------------------------------------
// Visitor to find string function calls (strcpy, memcpy, etc.)
//--------------------------------------------------------------------------
struct string_call_visitor_t : public ctree_visitor_t {
    cfunc_t *cfunc;
    std::vector<ctree_string_decrypt_handler_t::string_reveal_t> reveals;
    std::vector<ctree_string_decrypt_handler_t::crypto_call_t> crypto_calls;
    
    string_call_visitor_t(cfunc_t *cf) : ctree_visitor_t(CV_FAST), cfunc(cf) {}
    
    int idaapi visit_expr(cexpr_t *e) override {
        if (e->op != cot_call)
            return 0;
            
        // Get the called function
        cexpr_t *callee = e->x;
        if (!callee)
            return 0;
            
        qstring func_name;
        if (!get_func_name(&func_name, callee))
            return 0;
            
        // Check for string copy functions (including __strcpy_chk, ___strcpy_chk variants)
        // Use substring matching to handle all underscore prefix/suffix variations
        if (func_name.find("strcpy") != qstring::npos ||
            func_name.find("strncpy") != qstring::npos ||
            func_name.find("strlcpy") != qstring::npos) {
            process_strcpy(e, func_name);
        }
        else if (func_name.find("memcpy") != qstring::npos ||
                 func_name.find("memmove") != qstring::npos ||
                 func_name.find("qmemcpy") != qstring::npos ||
                 func_name.find("bcopy") != qstring::npos ||
                 func_name.find("memset") != qstring::npos) {
            process_memcpy(e, func_name);
        }
        else if (func_name.find("CCCrypt") != qstring::npos ||
                 func_name.find("AES_decrypt") != qstring::npos ||
                 func_name.find("AES_cbc_encrypt") != qstring::npos ||
                 func_name.find("EVP_Decrypt") != qstring::npos ||
                 func_name.find("EVP_Cipher") != qstring::npos) {
            process_crypto_call(e, func_name);
        }
        
        return 0;
    }
    
private:
    bool get_func_name(qstring *out, cexpr_t *callee) {
        if (callee->op == cot_obj) {
            // Direct function reference
            if (get_name(out, callee->obj_ea) > 0)
                return true;
        }
        else if (callee->op == cot_helper) {
            // Helper function
            *out = callee->helper;
            return true;
        }
        return false;
    }
    
    void process_strcpy(cexpr_t *call, const qstring &func_name) {
        // strcpy(dest, src)
        carglist_t *args = call->a;
        if (!args || args->size() < 2)
            return;
            
        cexpr_t *dest = &(*args)[0];
        cexpr_t *src = &(*args)[1];
        
        // Check if source is a string constant
        qstring str_val;
        if (!extract_string_constant(src, &str_val))
            return;
            
        ctree_string_decrypt_handler_t::string_reveal_t reveal;
        reveal.location = call->ea;
        reveal.plaintext = str_val;
        reveal.reveal_type = 0;  // strcpy
        
        // Try to get destination info
        if (dest->op == cot_var) {
            lvars_t *lvars = cfunc->get_lvars();
            if (lvars && dest->v.idx < lvars->size()) {
                reveal.dest_name = (*lvars)[dest->v.idx].name;
            }
        } else if (dest->op == cot_obj) {
            reveal.dest_addr = dest->obj_ea;
            get_name(&reveal.dest_name, dest->obj_ea);
        }
        
        ctree_str_debug("[strcpy] Found: %s -> \"%s\"\n", 
                       reveal.dest_name.c_str(), str_val.c_str());
        
        reveals.push_back(reveal);
    }
    
    void process_memcpy(cexpr_t *call, const qstring &func_name) {
        // memcpy(dest, src, size)
        carglist_t *args = call->a;
        if (!args || args->size() < 3)
            return;
            
        cexpr_t *dest = &(*args)[0];
        cexpr_t *src = &(*args)[1];
        cexpr_t *size = &(*args)[2];
        
        // Check if source is a string constant
        qstring str_val;
        if (!extract_string_constant(src, &str_val))
            return;
            
        // Verify size matches (or close to it)
        if (size->op == cot_num) {
            uint64_t sz = size->numval();
            if (sz > 0 && sz < 4096 && sz >= str_val.length()) {
                // Size looks reasonable
            }
        }
        
        ctree_string_decrypt_handler_t::string_reveal_t reveal;
        reveal.location = call->ea;
        reveal.plaintext = str_val;
        reveal.reveal_type = 1;  // memcpy
        
        // Try to get destination info
        if (dest->op == cot_var) {
            lvars_t *lvars = cfunc->get_lvars();
            if (lvars && dest->v.idx < lvars->size()) {
                reveal.dest_name = (*lvars)[dest->v.idx].name;
            }
        } else if (dest->op == cot_obj) {
            reveal.dest_addr = dest->obj_ea;
            get_name(&reveal.dest_name, dest->obj_ea);
        }
        
        ctree_str_debug("[memcpy] Found: %s -> \"%s\" (len=%zu)\n",
                       reveal.dest_name.c_str(), str_val.c_str(), str_val.length());
        
        reveals.push_back(reveal);
    }
    
    void process_crypto_call(cexpr_t *call, const qstring &func_name) {
        // CCCrypt(op, alg, options, key, keyLen, iv, dataIn, dataInLen, dataOut, dataOutAvail, dataOutMoved)
        // Args:  0    1      2      3     4     5     6        7        8          9            10
        carglist_t *args = call->a;
        if (!args)
            return;
            
        ctree_string_decrypt_handler_t::crypto_call_t crypto;
        crypto.location = call->ea;
        crypto.function = func_name;
        crypto.input_addr = BADADDR;
        crypto.input_len = 0;
        crypto.output_addr = BADADDR;
        
        if (func_name == "CCCrypt" || func_name == "_CCCrypt") {
            if (args->size() >= 8) {
                // Get key (arg 3) and keyLen (arg 4)
                cexpr_t *key_arg = &(*args)[3];
                cexpr_t *keylen_arg = &(*args)[4];
                
                // Try to extract key if it's a string constant or global
                qstring key_str;
                if (extract_string_constant(key_arg, &key_str)) {
                    for (size_t i = 0; i < key_str.length(); i++) {
                        crypto.key.push_back((uint8_t)key_str[i]);
                    }
                } else if (key_arg->op == cot_obj) {
                    // Key is at a global address - try to read it
                    ea_t key_addr = key_arg->obj_ea;
                    size_t key_len = 16;  // Default to AES-128
                    if (keylen_arg->op == cot_num) {
                        key_len = (size_t)keylen_arg->numval();
                    }
                    if (key_addr != BADADDR && key_len <= 32) {
                        crypto.key.resize(key_len);
                        if (get_bytes(crypto.key.data(), key_len, key_addr) == key_len) {
                            ctree_str_debug("[crypto] Read key from 0x%llx (%zu bytes)\n",
                                           (unsigned long long)key_addr, key_len);
                        } else {
                            crypto.key.clear();
                        }
                    }
                }
                
                // Determine algorithm based on key length
                if (keylen_arg->op == cot_num) {
                    uint64_t keylen = keylen_arg->numval();
                    crypto.algorithm = (keylen == 32) ? 1 : 0;  // AES-256 or AES-128
                }
                
                // Try to get IV (arg 5)
                cexpr_t *iv_arg = &(*args)[5];
                qstring iv_str;
                if (extract_string_constant(iv_arg, &iv_str)) {
                    for (size_t i = 0; i < iv_str.length() && i < 16; i++) {
                        crypto.iv.push_back((uint8_t)iv_str[i]);
                    }
                } else if (iv_arg->op == cot_obj && iv_arg->obj_ea != BADADDR) {
                    // IV is at a global address
                    crypto.iv.resize(16);
                    if (get_bytes(crypto.iv.data(), 16, iv_arg->obj_ea) != 16) {
                        crypto.iv.clear();
                    }
                }
                
                // Get input data address and length (args 6 and 7)
                cexpr_t *data_in_arg = &(*args)[6];
                cexpr_t *data_in_len_arg = &(*args)[7];
                
                if (data_in_arg->op == cot_obj) {
                    crypto.input_addr = data_in_arg->obj_ea;
                }
                if (data_in_len_arg->op == cot_num) {
                    crypto.input_len = (size_t)data_in_len_arg->numval();
                }
                
                // Get output address (arg 8) if available
                if (args->size() >= 9) {
                    cexpr_t *data_out_arg = &(*args)[8];
                    if (data_out_arg->op == cot_obj) {
                        crypto.output_addr = data_out_arg->obj_ea;
                    }
                }
                
                // If we have key and input data, try to decrypt
                if (!crypto.key.empty() && crypto.input_addr != BADADDR && crypto.input_len > 0) {
                    ctree_str_debug("[crypto] Attempting AES decryption: input=0x%llx len=%zu key_len=%zu\n",
                                   (unsigned long long)crypto.input_addr, crypto.input_len, crypto.key.size());
                    
                    if (try_aes_decrypt_at_address(crypto.input_addr, crypto.input_len,
                                                   crypto.key, crypto.iv, &crypto.decrypted)) {
                        ctree_str_debug("[crypto] Decryption SUCCESS: \"%s\"\n", crypto.decrypted.c_str());
                    }
                }
                
                if (!crypto.key.empty()) {
                    ctree_str_debug("[crypto] Found CCCrypt: key_len=%zu iv_len=%zu input=0x%llx len=%zu\n",
                                   crypto.key.size(), crypto.iv.size(),
                                   (unsigned long long)crypto.input_addr, crypto.input_len);
                    crypto_calls.push_back(crypto);
                }
            }
        }
    }
    
    bool extract_string_constant(cexpr_t *e, qstring *out) {
        if (!e || !out)
            return false;
            
        // Direct string constant
        if (e->op == cot_str) {
            *out = e->string;
            return true;
        }
        
        // Reference to global string
        if (e->op == cot_obj) {
            // Try to read string from address
            ea_t addr = e->obj_ea;
            if (addr != BADADDR) {
                qstring buf;
                ssize_t len = get_strlit_contents(&buf, addr, -1, STRTYPE_C);
                if (len > 0) {
                    *out = buf;
                    return true;
                }
                // Also try just reading bytes
                len = get_max_strlit_length(addr, STRTYPE_C, ALOPT_IGNCLT);
                if (len > 0 && len < 1024) {
                    char raw_buf[1024];
                    get_bytes(raw_buf, len, addr);
                    raw_buf[len] = 0;
                    *out = raw_buf;
                    return true;
                }
            }
        }
        
        // Cast expression - unwrap and try again
        if (e->op == cot_cast) {
            return extract_string_constant(e->x, out);
        }
        
        // Reference expression
        if (e->op == cot_ref) {
            return extract_string_constant(e->x, out);
        }
        
        return false;
    }
};

//--------------------------------------------------------------------------
// Visitor to find character-by-character assignments
//--------------------------------------------------------------------------
struct char_assign_visitor_t : public ctree_visitor_t {
    cfunc_t *cfunc;
    
    // Map: variable -> (offset -> (value, ea))
    std::map<int, std::map<int, std::pair<uint8_t, ea_t>>> var_assignments;
    std::map<ea_t, std::map<int, std::pair<uint8_t, ea_t>>> global_assignments;
    
    char_assign_visitor_t(cfunc_t *cf) : ctree_visitor_t(CV_FAST), cfunc(cf) {}
    
    int idaapi visit_expr(cexpr_t *e) override {
        // Look for: var[index] = value
        if (e->op != cot_asg)
            return 0;
            
        cexpr_t *lhs = e->x;
        cexpr_t *rhs = e->y;
        
        if (!lhs || !rhs)
            return 0;
            
        // Value must be a constant (or simple transform of constant)
        uint8_t value;
        if (!extract_byte_value(rhs, &value))
            return 0;
        
        // Check for array index pattern: buffer[index] = value
        if (lhs->op == cot_idx) {
            cexpr_t *base = lhs->x;
            cexpr_t *index = lhs->y;
            
            if (!base || !index)
                return 0;
                
            // Index must be a constant
            if (index->op != cot_num)
                return 0;
            int idx = (int)index->numval();
                
            // Get the base variable
            if (base->op == cot_var) {
                int var_idx = base->v.idx;
                var_assignments[var_idx][idx] = std::make_pair(value, e->ea);
            }
            else if (base->op == cot_obj) {
                ea_t addr = base->obj_ea;
                global_assignments[addr][idx] = std::make_pair(value, e->ea);
            }
        }
        // Check for pointer dereference pattern: *buffer = value (index 0)
        else if (lhs->op == cot_ptr) {
            cexpr_t *ptr_expr = lhs->x;
            if (!ptr_expr)
                return 0;
            
            // Simple case: *buffer = value (index 0)
            if (ptr_expr->op == cot_var) {
                int var_idx = ptr_expr->v.idx;
                var_assignments[var_idx][0] = std::make_pair(value, e->ea);
            }
            else if (ptr_expr->op == cot_obj) {
                ea_t addr = ptr_expr->obj_ea;
                global_assignments[addr][0] = std::make_pair(value, e->ea);
            }
            // Pointer arithmetic: *(buffer + N) = value
            else if (ptr_expr->op == cot_add) {
                cexpr_t *base = ptr_expr->x;
                cexpr_t *offset = ptr_expr->y;
                
                // Handle both orderings: (var + num) or (num + var)
                if (base && offset) {
                    if (base->op == cot_num && offset->op != cot_num) {
                        std::swap(base, offset);
                    }
                    
                    if (offset->op == cot_num) {
                        int idx = (int)offset->numval();
                        
                        if (base->op == cot_var) {
                            int var_idx = base->v.idx;
                            var_assignments[var_idx][idx] = std::make_pair(value, e->ea);
                        }
                        else if (base->op == cot_obj) {
                            ea_t addr = base->obj_ea;
                            global_assignments[addr][idx] = std::make_pair(value, e->ea);
                        }
                        // Handle cast around variable: *((_BYTE*)buffer + N)
                        else if (base->op == cot_cast && base->x) {
                            cexpr_t *inner = base->x;
                            if (inner->op == cot_var) {
                                int var_idx = inner->v.idx;
                                var_assignments[var_idx][idx] = std::make_pair(value, e->ea);
                            }
                            else if (inner->op == cot_obj) {
                                ea_t addr = inner->obj_ea;
                                global_assignments[addr][idx] = std::make_pair(value, e->ea);
                            }
                        }
                    }
                }
            }
            // Cast around the whole expression: *(_BYTE*)(buffer + N)
            else if (ptr_expr->op == cot_cast && ptr_expr->x && ptr_expr->x->op == cot_add) {
                cexpr_t *add_expr = ptr_expr->x;
                cexpr_t *base = add_expr->x;
                cexpr_t *offset = add_expr->y;
                
                if (base && offset) {
                    if (base->op == cot_num && offset->op != cot_num) {
                        std::swap(base, offset);
                    }
                    
                    if (offset->op == cot_num) {
                        int idx = (int)offset->numval();
                        
                        if (base->op == cot_var) {
                            int var_idx = base->v.idx;
                            var_assignments[var_idx][idx] = std::make_pair(value, e->ea);
                        }
                        else if (base->op == cot_obj) {
                            ea_t addr = base->obj_ea;
                            global_assignments[addr][idx] = std::make_pair(value, e->ea);
                        }
                    }
                }
            }
        }
        
        return 0;
    }
    
    // Convert collected assignments to strings
    std::vector<ctree_string_decrypt_handler_t::char_string_t> 
    get_reconstructed_strings() {
        std::vector<ctree_string_decrypt_handler_t::char_string_t> result;
        
        // Process local variable assignments
        lvars_t *lvars = cfunc->get_lvars();
        for (auto &kv : var_assignments) {
            int var_idx = kv.first;
            auto &offsets = kv.second;
            
            if (offsets.size() < 3)
                continue;
                
            ctree_string_decrypt_handler_t::char_string_t str;
            
            if (lvars && var_idx < lvars->size()) {
                str.var_name = (*lvars)[var_idx].name;
            } else {
                str.var_name.sprnt("var_%d", var_idx);
            }
            
            if (try_reconstruct(offsets, &str)) {
                ctree_str_debug("[char_assign] Variable %s: \"%s\"\n",
                               str.var_name.c_str(), str.reconstructed.c_str());
                result.push_back(str);
            }
        }
        
        // Process global assignments
        for (auto &kv : global_assignments) {
            ea_t addr = kv.first;
            auto &offsets = kv.second;
            
            if (offsets.size() < 3)
                continue;
                
            ctree_string_decrypt_handler_t::char_string_t str;
            str.var_addr = addr;
            get_name(&str.var_name, addr);
            if (str.var_name.empty()) {
                str.var_name.sprnt("global_%llX", (unsigned long long)addr);
            }
            
            if (try_reconstruct(offsets, &str)) {
                ctree_str_debug("[char_assign] Global %s: \"%s\"\n",
                               str.var_name.c_str(), str.reconstructed.c_str());
                result.push_back(str);
            }
        }
        
        return result;
    }
    
private:
    bool extract_byte_value(cexpr_t *e, uint8_t *out) {
        if (!e)
            return false;
            
        // Direct number
        if (e->op == cot_num) {
            *out = (uint8_t)(e->numval() & 0xFF);
            return true;
        }
        
        // NOT (~) operation
        if (e->op == cot_bnot && e->x && e->x->op == cot_num) {
            *out = (uint8_t)(~e->x->numval() & 0xFF);
            return true;
        }
        
        // XOR operation with constants
        if (e->op == cot_xor) {
            uint8_t left = 0, right = 0;
            if (e->x && e->x->op == cot_num)
                left = (uint8_t)(e->x->numval() & 0xFF);
            if (e->y && e->y->op == cot_num)
                right = (uint8_t)(e->y->numval() & 0xFF);
            *out = left ^ right;
            return true;
        }
        
        // Cast expression
        if (e->op == cot_cast) {
            return extract_byte_value(e->x, out);
        }
        
        return false;
    }
    
    bool try_reconstruct(const std::map<int, std::pair<uint8_t, ea_t>> &offsets,
                         ctree_string_decrypt_handler_t::char_string_t *out) {
        if (offsets.empty())
            return false;
            
        // Find the range of indices
        int min_idx = offsets.begin()->first;
        int max_idx = offsets.rbegin()->first;
        
        // Check for reasonable string length
        if (max_idx - min_idx > 4096)
            return false;
            
        // Build the string
        qstring str;
        bool all_printable = true;
        
        for (int i = min_idx; i <= max_idx; i++) {
            auto it = offsets.find(i);
            if (it == offsets.end()) {
                // Gap in assignments - might be end of string
                break;
            }
            
            uint8_t c = it->second.first;
            out->insn_addrs.push_back(it->second.second);
            
            if (c == 0) {
                // Null terminator
                break;
            }
            
            if (c < 0x20 || c > 0x7E) {
                if (c != '\n' && c != '\r' && c != '\t') {
                    all_printable = false;
                    break;
                }
            }
            
            str += (char)c;
        }
        
        if (!all_printable || str.length() < 3)
            return false;
            
        out->reconstructed = str;
        if (!out->insn_addrs.empty()) {
            out->start_addr = out->insn_addrs[0];
        }
        
        return true;
    }
};

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool ctree_string_decrypt_handler_t::detect(cfunc_t *cfunc) {
    if (!cfunc)
        return false;
        
    // Quick check: does the function have string-related calls?
    struct quick_visitor_t : public ctree_visitor_t {
        bool found = false;
        
        quick_visitor_t() : ctree_visitor_t(CV_FAST) {}
        
        int idaapi visit_expr(cexpr_t *e) override {
            if (found)
                return 1;  // Stop visiting
                
            if (e->op == cot_call && e->x) {
                cexpr_t *callee = e->x;
                qstring name;
                
                // Check for direct function reference
                if (callee->op == cot_obj) {
                    get_name(&name, callee->obj_ea);
                }
                // Check for helper function (used by decompiler for recognized patterns)
                else if (callee->op == cot_helper) {
                    name = callee->helper;
                }
                
                if (!name.empty()) {
                    if (name.find("strcpy") != qstring::npos ||
                        name.find("memcpy") != qstring::npos ||
                        name.find("qmemcpy") != qstring::npos ||
                        name.find("CCCrypt") != qstring::npos) {
                        found = true;
                        return 1;
                    }
                }
            }
            
            // Check for array index assignments: buffer[i] = value
            if (e->op == cot_asg && e->x && e->x->op == cot_idx) {
                found = true;
                return 1;
            }
            
            // Check for pointer dereference assignments: *buffer = value, *(buffer+i) = value
            if (e->op == cot_asg && e->x && e->x->op == cot_ptr) {
                found = true;
                return 1;
            }
            
            return 0;
        }
    } visitor;
    
    visitor.apply_to(&cfunc->body, nullptr);
    return visitor.found;
}

//--------------------------------------------------------------------------
// Main entry point
//--------------------------------------------------------------------------
int ctree_string_decrypt_handler_t::run(cfunc_t *cfunc, deobf_ctx_t *ctx) {
    if (!cfunc || !ctx)
        return 0;
        
    ctree_str_debug("[ctree_string] Analyzing function at 0x%llx\n",
                   (unsigned long long)cfunc->entry_ea);
    
    int total_changes = 0;
    
    // Find string function calls (strcpy, memcpy, CCCrypt)
    string_call_visitor_t call_visitor(cfunc);
    call_visitor.apply_to(&cfunc->body, nullptr);
    
    for (const auto &reveal : call_visitor.reveals) {
        // Store in context
        if (reveal.dest_addr != BADADDR) {
            ctx->decrypted_strings[reveal.dest_addr] = reveal.plaintext.c_str();
        }
        
        // Annotate
        annotate_reveal(reveal);
        total_changes++;
    }
    
    for (const auto &crypto : call_visitor.crypto_calls) {
        // Store decrypted result in context if available
        if (!crypto.decrypted.empty()) {
            if (crypto.input_addr != BADADDR) {
                ctx->decrypted_strings[crypto.input_addr] = crypto.decrypted.c_str();
            }
            if (crypto.output_addr != BADADDR) {
                ctx->decrypted_strings[crypto.output_addr] = crypto.decrypted.c_str();
            }
            ctx->strings_decrypted++;
        }
        
        annotate_crypto_call(crypto);
        total_changes++;
    }
    
    // Find character-by-character assignments
    char_assign_visitor_t assign_visitor(cfunc);
    assign_visitor.apply_to(&cfunc->body, nullptr);
    
    auto char_strings = assign_visitor.get_reconstructed_strings();
    for (const auto &str : char_strings) {
        // Store in context
        if (str.var_addr != BADADDR) {
            ctx->decrypted_strings[str.var_addr] = str.reconstructed.c_str();
        }
        
        // Annotate
        annotate_char_string(str);
        total_changes++;
    }
    
    ctree_str_debug("[ctree_string] Found %zu strcpy/memcpy reveals, %zu crypto calls, %zu char strings\n",
                   call_visitor.reveals.size(), call_visitor.crypto_calls.size(), char_strings.size());
    
    // Phase 2: Find encrypted strings in ctree and replace with decrypted values
    // Build a map of destination addresses -> plaintexts from ALL sources
    std::map<ea_t, qstring> addr_to_plaintext;
    
    // Add strcpy/memcpy reveals
    for (const auto &reveal : call_visitor.reveals) {
        if (reveal.dest_addr != BADADDR && !reveal.plaintext.empty()) {
            addr_to_plaintext[reveal.dest_addr] = reveal.plaintext;
            ctree_str_debug("[mapping] strcpy/memcpy: 0x%llx -> \"%s\"\n",
                           (unsigned long long)reveal.dest_addr, reveal.plaintext.c_str());
        }
    }
    
    // Add character-by-character reconstructed strings
    for (const auto &str : char_strings) {
        if (str.var_addr != BADADDR && !str.reconstructed.empty()) {
            addr_to_plaintext[str.var_addr] = str.reconstructed;
            ctree_str_debug("[mapping] char-by-char: 0x%llx -> \"%s\"\n",
                           (unsigned long long)str.var_addr, str.reconstructed.c_str());
        }
    }
    
    // Add crypto call results
    for (const auto &crypto : call_visitor.crypto_calls) {
        if (!crypto.decrypted.empty()) {
            if (crypto.input_addr != BADADDR) {
                addr_to_plaintext[crypto.input_addr] = crypto.decrypted;
                ctree_str_debug("[mapping] crypto input: 0x%llx -> \"%s\"\n",
                               (unsigned long long)crypto.input_addr, crypto.decrypted.c_str());
            }
            if (crypto.output_addr != BADADDR) {
                addr_to_plaintext[crypto.output_addr] = crypto.decrypted;
            }
        }
    }
    
    ctree_str_debug("[ctree_string] Built address->plaintext map with %zu entries\n", addr_to_plaintext.size());
    
    if (!addr_to_plaintext.empty()) {
        int replaced = replace_encrypted_strings(cfunc, addr_to_plaintext);
        if (replaced > 0) {
            ctree_str_debug("[ctree_string] Replaced %d encrypted strings in ctree\n", replaced);
            total_changes += replaced;
        }
    }
    
    return total_changes;
}

//--------------------------------------------------------------------------
// Encrypted string replacement visitor
//--------------------------------------------------------------------------
struct encrypted_string_replacer_t : public ctree_visitor_t {
    cfunc_t *cfunc;
    const std::map<ea_t, qstring> &known_plaintexts;
    int replacements = 0;
    
    encrypted_string_replacer_t(cfunc_t *cf, const std::map<ea_t, qstring> &plaintexts)
        : ctree_visitor_t(CV_FAST), cfunc(cf), known_plaintexts(plaintexts) {}
    
    // Check if data at address looks encrypted (has non-printable chars)
    static bool is_encrypted_string(ea_t addr, size_t max_len = 256) {
        if (addr == BADADDR || !is_loaded(addr))
            return false;
            
        int non_printable = 0;
        int total = 0;
        
        for (size_t i = 0; i < max_len; i++) {
            uint8_t c = get_byte(addr + i);
            if (c == 0) break;
            total++;
            if (c < 0x20 || c > 0x7E) {
                if (c != '\n' && c != '\r' && c != '\t') {
                    non_printable++;
                }
            }
        }
        
        // Consider encrypted if >30% non-printable and at least 4 chars
        return total >= 4 && non_printable > 0 && (non_printable * 100 / total) > 30;
    }
    
    // Try to decrypt using XOR with known plaintext
    static bool try_xor_decrypt(ea_t encrypted_addr, const qstring &known_plain, qstring *out) {
        if (encrypted_addr == BADADDR || known_plain.empty())
            return false;
            
        size_t len = known_plain.length();
        
        // Read encrypted data
        std::vector<uint8_t> encrypted(len);
        if (get_bytes(encrypted.data(), len, encrypted_addr) != len)
            return false;
        
        // Compute XOR key by XORing encrypted with known plaintext
        std::vector<uint8_t> key(len);
        for (size_t i = 0; i < len; i++) {
            key[i] = encrypted[i] ^ (uint8_t)known_plain[i];
        }
        
        // Verify by decrypting - should get plaintext back
        qstring decrypted;
        for (size_t i = 0; i < len; i++) {
            char c = encrypted[i] ^ key[i];
            if (c == 0) break;
            decrypted += c;
        }
        
        if (decrypted == known_plain) {
            *out = decrypted;
            return true;
        }
        
        return false;
    }
    
    // Helper to get op name for debugging
    static const char* get_op_name(ctype_t op) {
        switch(op) {
            case cot_comma: return "cot_comma";
            case cot_asg: return "cot_asg";
            case cot_asgbor: return "cot_asgbor";
            case cot_asgxor: return "cot_asgxor";
            case cot_asgband: return "cot_asgband";
            case cot_asgadd: return "cot_asgadd";
            case cot_asgsub: return "cot_asgsub";
            case cot_asgmul: return "cot_asgmul";
            case cot_asgsshr: return "cot_asgsshr";
            case cot_asgushr: return "cot_asgushr";
            case cot_asgshl: return "cot_asgshl";
            case cot_asgsdiv: return "cot_asgsdiv";
            case cot_asgudiv: return "cot_asgudiv";
            case cot_asgsmod: return "cot_asgsmod";
            case cot_asgumod: return "cot_asgumod";
            case cot_tern: return "cot_tern";
            case cot_lor: return "cot_lor";
            case cot_land: return "cot_land";
            case cot_bor: return "cot_bor";
            case cot_xor: return "cot_xor";
            case cot_band: return "cot_band";
            case cot_eq: return "cot_eq";
            case cot_ne: return "cot_ne";
            case cot_sge: return "cot_sge";
            case cot_uge: return "cot_uge";
            case cot_sle: return "cot_sle";
            case cot_ule: return "cot_ule";
            case cot_sgt: return "cot_sgt";
            case cot_ugt: return "cot_ugt";
            case cot_slt: return "cot_slt";
            case cot_ult: return "cot_ult";
            case cot_sshr: return "cot_sshr";
            case cot_ushr: return "cot_ushr";
            case cot_shl: return "cot_shl";
            case cot_add: return "cot_add";
            case cot_sub: return "cot_sub";
            case cot_mul: return "cot_mul";
            case cot_sdiv: return "cot_sdiv";
            case cot_udiv: return "cot_udiv";
            case cot_smod: return "cot_smod";
            case cot_umod: return "cot_umod";
            case cot_fadd: return "cot_fadd";
            case cot_fsub: return "cot_fsub";
            case cot_fmul: return "cot_fmul";
            case cot_fdiv: return "cot_fdiv";
            case cot_fneg: return "cot_fneg";
            case cot_neg: return "cot_neg";
            case cot_cast: return "cot_cast";
            case cot_lnot: return "cot_lnot";
            case cot_bnot: return "cot_bnot";
            case cot_ptr: return "cot_ptr";
            case cot_ref: return "cot_ref";
            case cot_postinc: return "cot_postinc";
            case cot_postdec: return "cot_postdec";
            case cot_preinc: return "cot_preinc";
            case cot_predec: return "cot_predec";
            case cot_call: return "cot_call";
            case cot_idx: return "cot_idx";
            case cot_memref: return "cot_memref";
            case cot_memptr: return "cot_memptr";
            case cot_num: return "cot_num";
            case cot_fnum: return "cot_fnum";
            case cot_str: return "cot_str";
            case cot_obj: return "cot_obj";
            case cot_var: return "cot_var";
            case cot_insn: return "cot_insn";
            case cot_sizeof: return "cot_sizeof";
            case cot_helper: return "cot_helper";
            case cot_type: return "cot_type";
            default: return "unknown";
        }
    }
    
    int idaapi visit_expr(cexpr_t *e) override {
        // Log all calls to understand what patterns exist
        if (e->op == cot_call && e->x) {
            const char *call_name = "unknown";
            if (e->x->op == cot_helper) {
                call_name = e->x->helper;
            } else if (e->x->op == cot_obj) {
                static char name_buf[256];
                qstring name;
                if (get_name(&name, e->x->obj_ea) > 0) {
                    qstrncpy(name_buf, name.c_str(), sizeof(name_buf));
                    call_name = name_buf;
                }
            }
            
            // Log call details with args
            if (e->a && e->a->size() > 0) {
                qstring args_info;
                for (size_t i = 0; i < e->a->size() && i < 3; i++) {
                    cexpr_t *arg = &(*e->a)[i];
                    args_info.cat_sprnt(" arg%zu:%s", i, get_op_name(arg->op));
                    if (arg->op == cot_str && arg->string) {
                        size_t len = strlen(arg->string);
                        qstring hex;
                        for (size_t j = 0; j < len && j < 8; j++) {
                            hex.cat_sprnt("%02X", (uint8_t)arg->string[j]);
                        }
                        args_info.cat_sprnt("(hex=%s)", hex.c_str());
                    } else if (arg->op == cot_obj) {
                        args_info.cat_sprnt("(0x%llx)", (unsigned long long)arg->obj_ea);
                    }
                }
                ctree_str_debug("[call] %s%s\n", call_name, args_info.c_str());
            }
        }
        
        // Look for CFSTR or string references that might be encrypted
        // CFSTR appears as: call to CFSTR helper with cot_obj argument
        // Or direct cot_obj/cot_str
        
        ea_t str_addr = BADADDR;
        const char *existing_str = nullptr;
        cexpr_t *target_expr = e;  // Expression to modify
        
        // Check for CFSTR(x) call pattern - this is how IDA shows CFString references
        if (e->op == cot_call && e->x) {
            // Check both helper and regular call
            const char *func_name = nullptr;
            if (e->x->op == cot_helper) {
                func_name = e->x->helper;
                ctree_str_debug("[replace] Call to helper: %s\n", func_name);
            } else if (e->x->op == cot_obj) {
                qstring name;
                if (get_name(&name, e->x->obj_ea) > 0) {
                    static char name_buf[256];
                    qstrncpy(name_buf, name.c_str(), sizeof(name_buf));
                    func_name = name_buf;
                }
            }
            
            if (func_name && (strstr(func_name, "CFSTR") || strstr(func_name, "CFString") ||
                              strstr(func_name, "__CFString"))) {
                ctree_str_debug("[replace] Found CFSTR-like call: %s\n", func_name);
                // The argument to CFSTR is what we want to decrypt
                if (e->a && e->a->size() > 0) {
                    cexpr_t *arg = &(*e->a)[0];
                    ctree_str_debug("[replace] CFSTR arg op: %s\n", get_op_name(arg->op));
                    if (arg->op == cot_obj) {
                        str_addr = arg->obj_ea;
                        target_expr = arg;  // We'll modify the argument
                        ctree_str_debug("[replace] Found CFSTR() call, arg at 0x%llx\n",
                                       (unsigned long long)str_addr);
                    } else if (arg->op == cot_str && arg->string) {
                        existing_str = arg->string;
                        target_expr = arg;
                        ctree_str_debug("[replace] Found CFSTR() with string arg: \"%s\"\n",
                                       existing_str);
                    }
                }
            }
        }
        // Direct cot_obj reference
        else if (e->op == cot_obj) {
            str_addr = e->obj_ea;
        }
        // Direct cot_str 
        else if (e->op == cot_str && e->string) {
            existing_str = e->string;
            // Log raw bytes for debugging
            size_t slen = strlen(existing_str);
            qstring hex_dump;
            for (size_t i = 0; i < slen && i < 32; i++) {
                hex_dump.cat_sprnt("%02X ", (uint8_t)existing_str[i]);
            }
            ctree_str_debug("[replace] Found cot_str: len=%zu hex=[%s]\n", 
                           slen, hex_dump.c_str());
        } else {
            return 0;
        }
        
        if (str_addr == BADADDR && !existing_str)
            return 0;
        
        // Try to find matching plaintext
        qstring decrypted;
        bool found = false;
        
        // Case 1: We have an existing string (cot_str) - check if it's encrypted
        if (existing_str) {
            size_t enc_len = strlen(existing_str);
            
            // Check if it looks encrypted
            int non_printable = 0;
            for (size_t i = 0; i < enc_len; i++) {
                uint8_t c = (uint8_t)existing_str[i];
                if (c < 0x20 || c > 0x7E) {
                    if (c != '\n' && c != '\r' && c != '\t') {
                        non_printable++;
                    }
                }
            }
            
            // Skip if not encrypted (< 30% non-printable)
            if (enc_len < 4 || non_printable == 0 || (non_printable * 100 / enc_len) <= 30)
                return 0;
            
            // Try each known plaintext with XOR
            for (const auto &kv : known_plaintexts) {
                const qstring &plain = kv.second;
                
                // Length must match approximately
                if (plain.length() != enc_len && 
                    plain.length() != enc_len - 1 && 
                    plain.length() != enc_len + 1)
                    continue;
                
                // Try XOR decryption using the string bytes directly
                size_t min_len = std::min(enc_len, plain.length());
                qstring test_decrypt;
                bool valid = true;
                
                for (size_t i = 0; i < min_len; i++) {
                    uint8_t enc_byte = (uint8_t)existing_str[i];
                    uint8_t plain_byte = (uint8_t)plain[i];
                    uint8_t key_byte = enc_byte ^ plain_byte;
                    char dec_char = enc_byte ^ key_byte;
                    
                    if (dec_char == 0) break;
                    test_decrypt += dec_char;
                }
                
                // Check if decryption matches the known plaintext
                if (test_decrypt == plain) {
                    decrypted = plain;
                    found = true;
                    ctree_str_debug("[replace] Matched cot_str to known plaintext: \"%s\"\n", 
                                   decrypted.c_str());
                    break;
                }
            }
        }
        // Case 2: We have an address (cot_obj) - read from memory
        else if (str_addr != BADADDR) {
            // Check if this is a CFSTR - typically in __cfstring section
            segment_t *seg = getseg(str_addr);
            if (!seg)
                return 0;
                
            qstring seg_name;
            get_segm_name(&seg_name, seg);
            
            ea_t actual_str_addr = str_addr;
            
            ctree_str_debug("[replace] cot_obj at 0x%llx in segment %s\n", 
                           (unsigned long long)str_addr, seg_name.c_str());
            
            // Check if this looks like a CFString structure by checking name, segment, or layout
            qstring name_at_addr;
            get_name(&name_at_addr, str_addr);
            bool is_cfstring_struct = seg_name.find("cfstring") != qstring::npos ||
                                       name_at_addr.find("cfstr_") != qstring::npos ||
                                       name_at_addr.find("CFString") != qstring::npos ||
                                       name_at_addr.find("stru_") != qstring::npos;  // May be unnamed CFString
            
            // If it looks like a struct, verify it's actually a CFString by checking the layout
            // CFString layout: isa(8), flags(8), str_ptr(8), length(8)
            if (!is_cfstring_struct && seg_name == "__data") {
                // Check if this could be a CFString by validating the structure
                uint64_t maybe_flags = get_qword(str_addr + 0x08);
                ea_t maybe_ptr = get_qword(str_addr + 0x10);
                uint64_t maybe_len = get_qword(str_addr + 0x18);
                
                // Heuristic: flags should be non-zero but reasonable, ptr should be valid, len should be small
                if (maybe_flags != 0 && maybe_flags < 0x10000 &&
                    maybe_ptr != 0 && maybe_ptr != BADADDR && is_loaded(maybe_ptr) &&
                    maybe_len > 0 && maybe_len < 4096) {
                    // Check if the pointer points to a known plaintext address
                    auto it = known_plaintexts.find(maybe_ptr);
                    if (it != known_plaintexts.end()) {
                        is_cfstring_struct = true;
                        ctree_str_debug("[replace] Detected CFString structure by layout at 0x%llx (ptr=0x%llx)\n",
                                       (unsigned long long)str_addr, (unsigned long long)maybe_ptr);
                    }
                }
            }
            
            ctree_str_debug("[replace] Name at 0x%llx = '%s', is_cfstring=%d\n",
                           (unsigned long long)str_addr, name_at_addr.c_str(), is_cfstring_struct);
            
            // IMPORTANT: Only replace CFSTR references, not destination buffers
            // A CFSTR reference has a structure pointer that points to the string data
            // A destination buffer is just the raw data location (what strcpy writes to)
            // We skip non-CFSTR structures to avoid breaking strcpy/memcpy calls
            if (!is_cfstring_struct) {
                ctree_str_debug("[replace] Skipping non-CFSTR cot_obj at 0x%llx\n",
                               (unsigned long long)str_addr);
                return 0;
            }
            
            // Handle CFSTR structure - the actual string is at offset 0x10
            // CFString layout: isa(8), flags(8), str_ptr(8), length(8)
            ea_t ptr = get_qword(str_addr + 0x10);
            ctree_str_debug("[replace] Checking as CFSTR structure: ptr at +0x10 = 0x%llx\n",
                           (unsigned long long)ptr);
            if (ptr != 0 && ptr != BADADDR && is_loaded(ptr)) {
                // Validate: the length field should be reasonable
                uint64_t len = get_qword(str_addr + 0x18);
                if (len > 0 && len < 4096) {
                    actual_str_addr = ptr;
                    ctree_str_debug("[replace] Using CFSTR string ptr 0x%llx, len=%llu\n",
                                   (unsigned long long)ptr, (unsigned long long)len);
                }
            }
            
            // Check if string at this address is encrypted
            if (!is_encrypted_string(actual_str_addr)) {
                ctree_str_debug("[replace] String at 0x%llx not encrypted, skipping\n",
                               (unsigned long long)actual_str_addr);
                return 0;
            }
                
            ctree_str_debug("[replace] Found encrypted cot_obj at 0x%llx\n", 
                           (unsigned long long)actual_str_addr);
            
            // Get encrypted string length
            size_t enc_len = 0;
            for (size_t i = 0; i < 256; i++) {
                if (get_byte(actual_str_addr + i) == 0) break;
                enc_len++;
            }
            
            ctree_str_debug("[replace] Encrypted string at 0x%llx has len=%zu, have %zu known plaintexts\n",
                           (unsigned long long)actual_str_addr, enc_len, known_plaintexts.size());
            
            // First check: is there a direct match by address?
            auto it = known_plaintexts.find(actual_str_addr);
            if (it != known_plaintexts.end()) {
                decrypted = it->second;
                found = true;
                ctree_str_debug("[replace] Direct address match! Using plaintext: \"%s\"\n", decrypted.c_str());
            }
            
            // Try each known plaintext
            if (!found) {
                for (const auto &kv : known_plaintexts) {
                    const qstring &plain = kv.second;
                    
                    ctree_str_debug("[replace] Trying plaintext len=%zu vs enc_len=%zu\n", 
                                   plain.length(), enc_len);
                    
                    if (plain.length() != enc_len && 
                        plain.length() != enc_len - 1 && 
                        plain.length() != enc_len + 1)
                        continue;
                    
                    if (try_xor_decrypt(actual_str_addr, plain, &decrypted)) {
                        found = true;
                        ctree_str_debug("[replace] Decrypted cot_obj to: \"%s\"\n", decrypted.c_str());
                        break;
                    }
                }
            }
        }
        
        if (!found)
            return 0;
            
        // Add comment at the expression's address  
        if (target_expr->ea != BADADDR) {
            qstring comment;
            comment.sprnt("DEOBF: Decrypted CFSTR = \"%s\"", decrypted.c_str());
            set_cmt(target_expr->ea, comment.c_str(), false);
        }
        
        // Try to patch the CFString's string data in the IDB
        // This will make CFSTR() show the decrypted string on re-decompilation
        if (str_addr != BADADDR) {
            // Get the string pointer from CFString structure at +0x10
            ea_t string_data_ptr = get_qword(str_addr + 0x10);
            if (string_data_ptr != 0 && string_data_ptr != BADADDR && is_loaded(string_data_ptr)) {
                // Verify this pointer points to a known plaintext (i.e., it's a valid CFString)
                auto it = known_plaintexts.find(string_data_ptr);
                if (it != known_plaintexts.end()) {
                    // Patch the string data bytes  
                    size_t dec_len = decrypted.length();
                    for (size_t i = 0; i < dec_len; i++) {
                        patch_byte(string_data_ptr + i, (uint8_t)decrypted[i]);
                    }
                    // Null terminate
                    patch_byte(string_data_ptr + dec_len, 0);
                    
                    ctree_str_debug("[replace] Patched %zu bytes at 0x%llx with decrypted string\n",
                                   dec_len, (unsigned long long)string_data_ptr);
                }
            }
        }
        
        ctree_str_debug("[replace] Added comment at 0x%llx for \"%s\"\n",
                       (unsigned long long)target_expr->ea, decrypted.c_str());
        
        replacements++;
        return 0;
    }
};

int ctree_string_decrypt_handler_t::replace_encrypted_strings(
    cfunc_t *cfunc, 
    const std::map<ea_t, qstring> &known_plaintexts)
{
    encrypted_string_replacer_t replacer(cfunc, known_plaintexts);
    replacer.apply_to(&cfunc->body, nullptr);
    return replacer.replacements;
}

//--------------------------------------------------------------------------
// Find patterns - delegated to visitors
//--------------------------------------------------------------------------
std::vector<ctree_string_decrypt_handler_t::string_reveal_t>
ctree_string_decrypt_handler_t::find_strcpy_reveals(cfunc_t *cfunc) {
    string_call_visitor_t visitor(cfunc);
    visitor.apply_to(&cfunc->body, nullptr);
    return visitor.reveals;
}

std::vector<ctree_string_decrypt_handler_t::string_reveal_t>
ctree_string_decrypt_handler_t::find_memcpy_reveals(cfunc_t *cfunc) {
    // Already handled in string_call_visitor_t
    return find_strcpy_reveals(cfunc);
}

std::vector<ctree_string_decrypt_handler_t::char_string_t>
ctree_string_decrypt_handler_t::find_char_assignments(cfunc_t *cfunc) {
    char_assign_visitor_t visitor(cfunc);
    visitor.apply_to(&cfunc->body, nullptr);
    return visitor.get_reconstructed_strings();
}

std::vector<ctree_string_decrypt_handler_t::xor_decrypt_t>
ctree_string_decrypt_handler_t::find_xor_patterns(cfunc_t *cfunc) {
    // TODO: Implement XOR pattern detection at ctree level
    return {};
}

std::vector<ctree_string_decrypt_handler_t::crypto_call_t>
ctree_string_decrypt_handler_t::find_crypto_calls(cfunc_t *cfunc) {
    string_call_visitor_t visitor(cfunc);
    visitor.apply_to(&cfunc->body, nullptr);
    return visitor.crypto_calls;
}

//--------------------------------------------------------------------------
// Annotation
//--------------------------------------------------------------------------
void ctree_string_decrypt_handler_t::annotate_reveal(const string_reveal_t &reveal) {
    if (reveal.location == BADADDR)
        return;
        
    qstring comment;
    const char *type = (reveal.reveal_type == 0) ? "strcpy" : "memcpy";
    
    if (!reveal.dest_name.empty()) {
        comment.sprnt("DEOBF: %s reveals \"%s\" -> %s",
                     type, reveal.plaintext.c_str(), reveal.dest_name.c_str());
    } else {
        comment.sprnt("DEOBF: %s reveals \"%s\"", type, reveal.plaintext.c_str());
    }
    
    set_cmt(reveal.location, comment.c_str(), false);
    
    // Also annotate at destination if it's a global
    if (reveal.dest_addr != BADADDR) {
        qstring dest_comment;
        dest_comment.sprnt("Decrypted: \"%s\"", reveal.plaintext.c_str());
        set_cmt(reveal.dest_addr, dest_comment.c_str(), true);
    }
}

void ctree_string_decrypt_handler_t::annotate_char_string(const char_string_t &str) {
    if (str.insn_addrs.empty())
        return;
        
    qstring comment;
    comment.sprnt("DEOBF: Stack string \"%s\"", str.reconstructed.c_str());
    
    // Annotate at first instruction
    set_cmt(str.insn_addrs[0], comment.c_str(), false);
    
    // Also annotate at variable address if global
    if (str.var_addr != BADADDR) {
        qstring var_comment;
        var_comment.sprnt("Decrypted: \"%s\"", str.reconstructed.c_str());
        set_cmt(str.var_addr, var_comment.c_str(), true);
    }
}

void ctree_string_decrypt_handler_t::annotate_xor_decrypt(const xor_decrypt_t &xor_info) {
    if (xor_info.location == BADADDR)
        return;
        
    qstring comment;
    comment.sprnt("DEOBF: XOR decrypts to \"%s\"", xor_info.decrypted.c_str());
    set_cmt(xor_info.location, comment.c_str(), false);
}

void ctree_string_decrypt_handler_t::annotate_crypto_call(const crypto_call_t &crypto) {
    if (crypto.location == BADADDR)
        return;
        
    qstring comment;
    const char *alg = (crypto.algorithm == 1) ? "AES-256" : "AES-128";
    
    // Convert key to hex for display
    qstring key_hex;
    for (size_t i = 0; i < crypto.key.size() && i < 16; i++) {
        key_hex.cat_sprnt("%02X", crypto.key[i]);
    }
    if (crypto.key.size() > 16) {
        key_hex += "...";
    }
    
    // Include decrypted result if available
    if (!crypto.decrypted.empty()) {
        // Truncate long decrypted strings for comment
        qstring decrypted_display = crypto.decrypted;
        if (decrypted_display.length() > 64) {
            decrypted_display.resize(64);
            decrypted_display += "...";
        }
        comment.sprnt("DEOBF: %s %s -> \"%s\" (key=%s)", 
                     crypto.function.c_str(), alg, decrypted_display.c_str(), key_hex.c_str());
    } else {
        comment.sprnt("DEOBF: %s %s key=%s", crypto.function.c_str(), alg, key_hex.c_str());
    }
    
    set_cmt(crypto.location, comment.c_str(), false);
    
    // If we have decrypted data and an output address, annotate there too
    if (!crypto.decrypted.empty() && crypto.output_addr != BADADDR) {
        qstring output_comment;
        output_comment.sprnt("AES Decrypted: \"%s\"", crypto.decrypted.c_str());
        set_cmt(crypto.output_addr, output_comment.c_str(), true);
    }
    
    // Also annotate at input address with what was encrypted
    if (!crypto.decrypted.empty() && crypto.input_addr != BADADDR) {
        qstring input_comment;
        input_comment.sprnt("Encrypted data -> \"%s\"", crypto.decrypted.c_str());
        set_cmt(crypto.input_addr, input_comment.c_str(), true);
    }
}

//--------------------------------------------------------------------------
// Helper functions
//--------------------------------------------------------------------------
bool ctree_string_decrypt_handler_t::get_string_constant(const cexpr_t *e, qstring *out) {
    if (!e || !out)
        return false;
        
    if (e->op == cot_str) {
        *out = e->string;
        return true;
    }
    
    return false;
}

ea_t ctree_string_decrypt_handler_t::get_address_from_expr(const cexpr_t *e, cfunc_t *cfunc) {
    if (!e)
        return BADADDR;
        
    if (e->op == cot_obj) {
        return e->obj_ea;
    }
    
    if (e->op == cot_var && cfunc) {
        // Local variable - no address
        return BADADDR;
    }
    
    return BADADDR;
}

bool ctree_string_decrypt_handler_t::is_string_function(const cexpr_t *e, qstring *func_name) {
    if (!e || e->op != cot_call)
        return false;
        
    cexpr_t *callee = e->x;
    if (!callee || callee->op != cot_obj)
        return false;
        
    qstring name;
    if (get_name(&name, callee->obj_ea) <= 0)
        return false;
        
    if (name.find("strcpy") != qstring::npos ||
        name.find("strncpy") != qstring::npos ||
        name.find("memcpy") != qstring::npos ||
        name.find("memmove") != qstring::npos) {
        if (func_name)
            *func_name = name;
        return true;
    }
    
    return false;
}

bool ctree_string_decrypt_handler_t::is_crypto_function(const cexpr_t *e, qstring *func_name) {
    if (!e || e->op != cot_call)
        return false;
        
    cexpr_t *callee = e->x;
    if (!callee || callee->op != cot_obj)
        return false;
        
    qstring name;
    if (get_name(&name, callee->obj_ea) <= 0)
        return false;
        
    if (name.find("CCCrypt") != qstring::npos ||
        name.find("AES_") != qstring::npos ||
        name.find("EVP_") != qstring::npos ||
        name.find("aes_") != qstring::npos) {
        if (func_name)
            *func_name = name;
        return true;
    }
    
    return false;
}

bool ctree_string_decrypt_handler_t::get_const_value(const cexpr_t *e, uint64_t *out) {
    if (!e || !out)
        return false;
        
    if (e->op == cot_num) {
        *out = e->numval();
        return true;
    }
    
    return false;
}

bool ctree_string_decrypt_handler_t::get_buffer_contents(ea_t addr, size_t max_len,
                                                         std::vector<uint8_t> *out) {
    if (addr == BADADDR || !out)
        return false;
        
    out->resize(max_len);
    ssize_t read = get_bytes(out->data(), max_len, addr);
    if (read <= 0)
        return false;
        
    out->resize(read);
    return true;
}

int ctree_string_decrypt_handler_t::patch_ctree_reference(cfunc_t *cfunc, ea_t encrypted_addr,
                                                          const qstring &decrypted) {
    // TODO: Implement ctree patching to replace encrypted references
    // This is complex and requires careful modification of the ctree
    return 0;
}
