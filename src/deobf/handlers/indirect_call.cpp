#include "indirect_call.h"
#include "../analysis/cfg_analysis.h"

//--------------------------------------------------------------------------
// File-based debug logging
//--------------------------------------------------------------------------
#include <fcntl.h>
#include <unistd.h>

static void icall_debug(const char *fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    int len = qvsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    int fd = open("/tmp/indirect_call_debug.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        write(fd, buf, len);
        close(fd);
    }
}

//--------------------------------------------------------------------------
// Detection - look for indirect call patterns
//
// Pattern 1: icall with computed target
// Pattern 2: call with target loaded from table and modified
//--------------------------------------------------------------------------
bool indirect_call_handler_t::detect(mbl_array_t *mba) {
    if (!mba)
        return false;

    icall_debug("[indirect_call] detect() called for func 0x%llx\n", 
                (unsigned long long)mba->entry_ea);

    // Look for icall instructions or calls with complex computed targets
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Check for icall (indirect call)
            if (ins->opcode == m_icall) {
                icall_debug("[indirect_call] Found m_icall in block %d\n", i);
                return true;
            }

            // Check for call with computed target
            // A direct call has l operand as mop_v (global) or mop_a (address)
            // A computed call has l operand as mop_r (register) or mop_d (result of computation)
            if (ins->opcode == m_call) {
                if (ins->l.t == mop_r || ins->l.t == mop_d) {
                    icall_debug("[indirect_call] Found m_call with computed target in block %d\n", i);
                    return true;
                }
            }
        }
    }

    // Also check for the ctree pattern:
    // Global table pointer that looks like it's used for indirect calls
    // This is a heuristic based on Hikari's typical naming
    segment_t *seg = get_first_seg();
    while (seg) {
        if (seg->type == SEG_DATA) {
            ea_t ea = seg->start_ea;
            while (ea < seg->end_ea) {
                // Check if this looks like a code pointer table
                uint64_t first_val = 0;
                if (get_bytes(&first_val, 8, ea) == 8) {
                    if (first_val != 0 && is_code(get_flags((ea_t)first_val))) {
                        // This might be a code pointer table
                        // Check if it's referenced in the function
                        xrefblk_t xb;
                        for (bool ok = xb.first_to(ea, XREF_DATA); ok; ok = xb.next_to()) {
                            if (xb.from >= mba->entry_ea) {
                                func_t *func = get_func(mba->entry_ea);
                                if (func && xb.from < func->end_ea) {
                                    icall_debug("[indirect_call] Found code pointer table at 0x%llx referenced from function\n",
                                                (unsigned long long)ea);
                                    return true;
                                }
                            }
                        }
                    }
                }
                ea = next_head(ea, seg->end_ea);
                if (ea == BADADDR)
                    break;
            }
        }
        seg = get_next_seg(seg->start_ea);
    }

    icall_debug("[indirect_call] No indirect call patterns detected\n");
    return false;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int indirect_call_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    icall_debug("[indirect_call] run() called for func 0x%llx\n",
                (unsigned long long)mba->entry_ea);

    int total_changes = 0;

    // Find all indirect calls
    auto icalls = find_indirect_calls(mba);
    icall_debug("[indirect_call] Found %zu indirect calls\n", icalls.size());

    for (auto &ic : icalls) {
        mblock_t *blk = mba->get_mblock(ic.block_idx);
        if (!blk)
            continue;

        // Try to resolve the call
        if (ic.is_resolved) {
            int changes = replace_indirect_call(mba, blk, ic, ctx);
            if (changes > 0) {
                total_changes += changes;
                icall_debug("[indirect_call] Block %d: resolved indirect call to 0x%llx (%s)\n",
                            ic.block_idx, (unsigned long long)ic.resolved_target,
                            ic.target_name.c_str());
            }
        } else {
            // Annotate what we found
            annotate_indirect_call(blk, ic);
            icall_debug("[indirect_call] Block %d: could not resolve, annotated\n", ic.block_idx);
        }
    }

    icall_debug("[indirect_call] Total changes: %d\n", total_changes);
    return total_changes;
}

//--------------------------------------------------------------------------
// Find all indirect calls in the function
//
// NEW APPROACH: Also look for the Hikari pattern directly:
//   1. mov stkvar, &table (global table address to stack)
//   2. ldx from that stkvar with offset (load table[index])
//   3. sub loaded_val, #offset (apply obfuscation offset)
//   4. Eventually used in icall/call
//
// At early maturity, we can extract the pattern before it gets folded.
//--------------------------------------------------------------------------
std::vector<indirect_call_handler_t::indirect_call_t>
indirect_call_handler_t::find_indirect_calls(mbl_array_t *mba) {
    std::vector<indirect_call_t> result;

    if (!mba)
        return result;

    // First pass: look for explicit icall/call with computed target
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            bool is_indirect = false;

            // Check for icall
            if (ins->opcode == m_icall) {
                is_indirect = true;
            }
            // Check for call with computed target
            else if (ins->opcode == m_call) {
                if (ins->l.t == mop_r || ins->l.t == mop_d) {
                    is_indirect = true;
                }
            }

            if (is_indirect) {
                indirect_call_t ic;
                ic.block_idx = i;
                ic.call_insn = ins;
                ic.table_addr = BADADDR;
                ic.table_index = -1;
                ic.offset = 0;
                ic.resolved_target = BADADDR;
                ic.is_resolved = false;

                // Try to analyze and resolve
                if (analyze_indirect_call(blk, ins, &ic)) {
                    icall_debug("[indirect_call] Analyzed call in block %d: table=0x%llx, index=%d, offset=%lld\n",
                                i, (unsigned long long)ic.table_addr, ic.table_index, (long long)ic.offset);
                }

                result.push_back(ic);
            }
        }
    }

    // If no icalls found, try to find the Hikari pattern at early maturity
    // Look for: sub reg, ldx_result, #large_offset
    if (result.empty()) {
        icall_debug("[indirect_call] No icall found, scanning for Hikari sub pattern...\n");
        icall_debug("[indirect_call] Maturity=%d, num_blocks=%d\n", mba->maturity, mba->qty);
        
        // Dump all subs to see what's there
        for (int i = 0; i < mba->qty; i++) {
            mblock_t *blk = mba->get_mblock(i);
            if (!blk) continue;
            for (minsn_t *ins = blk->head; ins; ins = ins->next) {
                if (ins->opcode == m_sub) {
                    icall_debug("[indirect_call]   sub at 0x%llx: l.t=%d r.t=%d d.t=%d",
                                (unsigned long long)ins->ea, ins->l.t, ins->r.t, ins->d.t);
                    if (ins->r.t == mop_n)
                        icall_debug(" r=#0x%llx", (unsigned long long)ins->r.nnn->value);
                    icall_debug("\n");
                }
            }
        }
        
        for (int i = 0; i < mba->qty; i++) {
            mblock_t *blk = mba->get_mblock(i);
            if (!blk) continue;
            
            for (minsn_t *ins = blk->head; ins; ins = ins->next) {
                // Look for: sub reg, ?, #large_const
                // where large_const looks like an obfuscation offset (> 0x10000)
                if (ins->opcode == m_sub && ins->r.t == mop_n) {
                    int64_t offset = ins->r.nnn->value;
                    if (offset > 0x10000 && offset < 0x1000000) {
                        icall_debug("[indirect_call] Found potential offset sub at 0x%llx: offset=%lld\n",
                                    (unsigned long long)ins->ea, (long long)offset);
                        
                        // This might be part of the pattern - create a placeholder
                        indirect_call_t ic;
                        ic.block_idx = i;
                        ic.call_insn = ins;  // Not actually a call, but the sub
                        ic.table_addr = BADADDR;
                        ic.table_index = -1;
                        ic.offset = offset;
                        ic.resolved_target = BADADDR;
                        ic.is_resolved = false;
                        
                        // Try to find table address from mov instructions
                        for (minsn_t *prev = blk->head; prev != ins; prev = prev->next) {
                            if (prev->opcode == m_mov && prev->l.t == mop_a && prev->l.a) {
                                if (prev->l.a->t == mop_v) {
                                    ea_t global = prev->l.a->g;
                                    uint64_t first_entry = 0;
                                    if (get_bytes(&first_entry, 8, global) == 8) {
                                        if (first_entry != 0 && is_code(get_flags((ea_t)first_entry))) {
                                            ic.table_addr = global;
                                            icall_debug("[indirect_call]   Table candidate: 0x%llx\n",
                                                        (unsigned long long)global);
                                        }
                                    }
                                }
                            }
                            // Look for ldx with constant offset
                            if (prev->opcode == m_ldx && prev->r.t == mop_n) {
                                ic.table_index = (int)(prev->r.nnn->value / 8);
                                icall_debug("[indirect_call]   Index from ldx: %d\n", ic.table_index);
                            }
                        }
                        
                        // If we have all components, try to resolve
                        if (ic.table_addr != BADADDR && ic.table_index >= 0) {
                            ic.resolved_target = compute_target(ic.table_addr, ic.table_index, ic.offset);
                            if (ic.resolved_target != BADADDR) {
                                ic.is_resolved = true;
                                get_name(&ic.target_name, ic.resolved_target);
                                icall_debug("[indirect_call]   RESOLVED: 0x%llx (%s)\n",
                                            (unsigned long long)ic.resolved_target,
                                            ic.target_name.c_str());
                                result.push_back(ic);
                            }
                        }
                    }
                }
            }
        }
    }

    return result;
}

//--------------------------------------------------------------------------
// Analyze an indirect call to extract table/index/offset
//
// We're looking for patterns like:
//   sub reg1, ldx(...), #offset   ; or
//   add reg1, ldx(...), #-offset
// followed by:
//   icall reg1
//
// Or at higher levels:
//   reg1 = table[index] - offset
//   call reg1
//--------------------------------------------------------------------------
bool indirect_call_handler_t::analyze_indirect_call(mblock_t *blk, minsn_t *call_insn,
                                                    indirect_call_t *out) {
    if (!blk || !call_insn || !out)
        return false;

    icall_debug("[indirect_call] Analyzing call at ea=0x%llx, opcode=%d\n", 
                (unsigned long long)call_insn->ea, call_insn->opcode);
    icall_debug("[indirect_call]   l.t=%d, r.t=%d, d.t=%d\n", 
                call_insn->l.t, call_insn->r.t, call_insn->d.t);
    if (call_insn->l.t == mop_r) {
        icall_debug("[indirect_call]   l.r=%d (target register)\n", call_insn->l.r);
    }
    // Dump all instructions in ALL blocks to find the target computation
    icall_debug("[indirect_call]   Dumping all blocks looking for table reference:\n");
    mbl_array_t *mba_dump = blk->mba;
    for (int bi = 0; bi < mba_dump->qty; bi++) {
        mblock_t *dump_blk = mba_dump->get_mblock(bi);
        if (!dump_blk) continue;
        icall_debug("[indirect_call]   Block %d:\n", bi);
        for (minsn_t *ins = dump_blk->head; ins; ins = ins->next) {
            icall_debug("[indirect_call]     ea=%llx op=%d l.t=%d r.t=%d d.t=%d",
                        (unsigned long long)ins->ea, ins->opcode, ins->l.t, ins->r.t, ins->d.t);
            if (ins->d.t == mop_r)
                icall_debug(" -> reg%d", ins->d.r);
            if (ins->d.t == mop_f)
                icall_debug(" -> stkvar");
            if (ins->l.t == mop_r)
                icall_debug(" from reg%d", ins->l.r);
            if (ins->l.t == mop_n)
                icall_debug(" from #0x%llx", (unsigned long long)ins->l.nnn->value);
            if (ins->l.t == mop_v)
                icall_debug(" from global 0x%llx", (unsigned long long)ins->l.g);
            if (ins->l.t == mop_a && ins->l.a) {
                icall_debug(" from &");
                if (ins->l.a->t == mop_v)
                    icall_debug("global 0x%llx", (unsigned long long)ins->l.a->g);
                else
                    icall_debug("(type %d)", ins->l.a->t);
            }
            if (ins->r.t == mop_a && ins->r.a) {
                icall_debug(" r=&");
                if (ins->r.a->t == mop_v)
                    icall_debug("global 0x%llx", (unsigned long long)ins->r.a->g);
            }
            // For ldx, the base address comes from r operand
            if (ins->opcode == m_ldx) {
                icall_debug(" [ldx: base.t=%d, idx.t=%d]", ins->l.t, ins->r.t);
            }
            // Check for sub instruction with table pattern
            if (ins->opcode == m_sub || ins->opcode == m_ldx) {
                icall_debug(" [INTERESTING]");
            }
            icall_debug("\n");
        }
    }

    // For m_icall, the structure depends on maturity level
    // At early maturity: icall l_operand (target in l)
    // At later maturity: might be different
    // 
    // Let's check all operands to understand the structure
    mop_t *target_op = nullptr;
    
    if (call_insn->opcode == m_icall) {
        // m_icall: target address is typically in l operand
        if (call_insn->l.t != mop_z) {
            target_op = &call_insn->l;
            icall_debug("[indirect_call]   Using l operand (type %d)\n", call_insn->l.t);
        } else if (call_insn->d.t != mop_z) {
            target_op = &call_insn->d;
            icall_debug("[indirect_call]   Using d operand (type %d)\n", call_insn->d.t);
        }
    } else if (call_insn->opcode == m_call) {
        if (call_insn->l.t == mop_d || call_insn->l.t == mop_r) {
            target_op = &call_insn->l;
            icall_debug("[indirect_call]   Using call l operand (type %d)\n", call_insn->l.t);
        }
    }

    if (!target_op) {
        icall_debug("[indirect_call]   No target operand found (all types: l=%d, r=%d, d=%d)\n",
                    call_insn->l.t, call_insn->r.t, call_insn->d.t);
        return false;
    }

    icall_debug("[indirect_call]   Target operand type: %d\n", target_op->t);

    // Trace back to find the computation
    ea_t table_addr = BADADDR;
    int table_index = -1;
    int64_t offset = 0;

    if (trace_call_target(blk, call_insn, &table_addr, &table_index, &offset)) {
        out->table_addr = table_addr;
        out->table_index = table_index;
        out->offset = offset;

        icall_debug("[indirect_call]   Traced: table=0x%llx, index=%d, offset=%lld\n",
                    (unsigned long long)table_addr, table_index, (long long)offset);

        // If we have a constant index, resolve the target
        if (table_addr != BADADDR && table_index >= 0) {
            out->resolved_target = compute_target(table_addr, table_index, offset);
            if (out->resolved_target != BADADDR) {
                out->is_resolved = true;
                get_name(&out->target_name, out->resolved_target);
                icall_debug("[indirect_call]   Resolved to 0x%llx (%s)\n",
                            (unsigned long long)out->resolved_target,
                            out->target_name.c_str());
            }
        }

        return true;
    }

    icall_debug("[indirect_call]   Could not trace call target\n");
    return false;
}

//--------------------------------------------------------------------------
// Trace the call target computation backwards
//
// NEW APPROACH: Instead of tracking registers, look for patterns in microcode:
// 1. Find mov of global table address to stack variable
// 2. Find ldx that loads from that table (with index offset)
// 3. Find sub instruction that subtracts the obfuscation offset
// 4. Connect to the icall
//--------------------------------------------------------------------------
bool indirect_call_handler_t::trace_call_target(mblock_t *blk, minsn_t *call_insn,
                                                ea_t *out_table, int *out_index,
                                                int64_t *out_offset) {
    if (!blk || !call_insn || !blk->mba)
        return false;

    *out_table = BADADDR;
    *out_index = -1;
    *out_offset = 0;

    mbl_array_t *mba = blk->mba;

    // Strategy: Look for the pattern directly
    // 1. mov stkvar, &global_table  (stores table address to stack)
    // 2. ldx ... from stkvar with offset (loads table[index])
    // 3. sub result, loaded_val, #offset
    // 4. icall result
    
    ea_t table_addr = BADADDR;
    int64_t load_offset = -1;
    int64_t sub_offset = 0;
    
    // Scan for global table reference (mov to stack)
    for (int bi = 0; bi < mba->qty; bi++) {
        mblock_t *scan_blk = mba->get_mblock(bi);
        if (!scan_blk) continue;
        
        for (minsn_t *ins = scan_blk->head; ins; ins = ins->next) {
            // Look for: mov stkvar, &global_table
            if (ins->opcode == m_mov && ins->l.t == mop_a && ins->l.a) {
                if (ins->l.a->t == mop_v) {
                    ea_t global = ins->l.a->g;
                    // Check if this looks like a code pointer table
                    uint64_t first_entry = 0;
                    if (get_bytes(&first_entry, 8, global) == 8) {
                        if (first_entry != 0 && is_code(get_flags((ea_t)first_entry))) {
                            table_addr = global;
                            icall_debug("[indirect_call]     Found table at 0x%llx\n",
                                        (unsigned long long)table_addr);
                        }
                    }
                }
            }
            
            // Look for ldx with numeric offset (this gives us the index)
            if (ins->opcode == m_ldx) {
                icall_debug("[indirect_call]     ldx at 0x%llx: l.t=%d, r.t=%d\n",
                            (unsigned long long)ins->ea, ins->l.t, ins->r.t);
                if (ins->r.t == mop_n) {
                    load_offset = ins->r.nnn->value;
                    icall_debug("[indirect_call]     Found ldx with offset %lld (index=%d)\n",
                                (long long)load_offset, (int)(load_offset / 8));
                }
            }
            
            // Look for sub with constant (this gives us the obfuscation offset)
            if (ins->opcode == m_sub && ins->r.t == mop_n) {
                sub_offset = ins->r.nnn->value;
                icall_debug("[indirect_call]     Found sub with offset %lld (0x%llx)\n",
                            (long long)sub_offset, (unsigned long long)sub_offset);
            }
        }
    }
    
    // If we found the table and offset, we can compute the target
    if (table_addr != BADADDR && load_offset >= 0 && sub_offset != 0) {
        *out_table = table_addr;
        *out_index = (int)(load_offset / 8);
        *out_offset = sub_offset;
        icall_debug("[indirect_call]     SUCCESS: table=0x%llx, index=%d, offset=%lld\n",
                    (unsigned long long)table_addr, *out_index, (long long)sub_offset);
        return true;
    }
    
    icall_debug("[indirect_call]     Pattern not found: table=%llx, load_off=%lld, sub_off=%lld\n",
                (unsigned long long)table_addr, (long long)load_offset, (long long)sub_offset);
    return false;
}

//--------------------------------------------------------------------------
// Find table base address from operand
//--------------------------------------------------------------------------
ea_t indirect_call_handler_t::find_table_base(mblock_t *blk, const mop_t &op) {
    if (op.t == mop_v) {
        return op.g;
    }
    if (op.t == mop_a && op.a && op.a->t == mop_v) {
        return op.a->g;
    }
    // Could trace through more complex expressions...
    return BADADDR;
}

//--------------------------------------------------------------------------
// Extract constant index from operand
//--------------------------------------------------------------------------
bool indirect_call_handler_t::extract_constant_index(mblock_t *blk, const mop_t &op,
                                                     int *out_index) {
    if (op.t == mop_n) {
        *out_index = (int)(op.nnn->value / 8);  // Assume 8-byte entries
        return true;
    }
    return false;
}

//--------------------------------------------------------------------------
// Read target from table and apply offset
//--------------------------------------------------------------------------
ea_t indirect_call_handler_t::compute_target(ea_t table_addr, int index, int64_t offset) {
    if (table_addr == BADADDR || index < 0)
        return BADADDR;

    ea_t entry_addr = table_addr + index * 8;  // 64-bit entries
    uint64_t entry_val = 0;

    if (get_bytes(&entry_val, 8, entry_addr) != 8) {
        icall_debug("[indirect_call]   Failed to read table entry at 0x%llx\n",
                    (unsigned long long)entry_addr);
        return BADADDR;
    }

    ea_t target = (ea_t)(entry_val - offset);

    icall_debug("[indirect_call]   table[%d] = 0x%llx, - %lld = 0x%llx\n",
                index, (unsigned long long)entry_val, (long long)offset,
                (unsigned long long)target);

    // Validate target is code
    if (is_code(get_flags(target))) {
        return target;
    }

    // Might still be valid if within function bounds
    func_t *func = get_func(target);
    if (func) {
        return target;
    }

    icall_debug("[indirect_call]   Target 0x%llx is not code\n", (unsigned long long)target);
    return BADADDR;
}

//--------------------------------------------------------------------------
// Replace indirect call with direct call
//--------------------------------------------------------------------------
int indirect_call_handler_t::replace_indirect_call(mbl_array_t *mba, mblock_t *blk,
                                                   indirect_call_t &ic, deobf_ctx_t *ctx) {
    if (!mba || !blk || !ic.call_insn || !ic.is_resolved)
        return 0;

    icall_debug("[indirect_call] Replacing call in block %d with direct call to 0x%llx\n",
                ic.block_idx, (unsigned long long)ic.resolved_target);

    minsn_t *call = ic.call_insn;

    // Convert to direct call
    // The target address goes in l operand as mop_v (global)
    call->opcode = m_call;
    call->l.make_gvar(ic.resolved_target);

    // Mark the block as modified
    blk->mark_lists_dirty();

    // Add comment
    qstring comment;
    comment.sprnt("DEOBF: Resolved indirect call -> %s (0x%llX)",
                  ic.target_name.empty() ? "?" : ic.target_name.c_str(),
                  (unsigned long long)ic.resolved_target);
    set_cmt(call->ea, comment.c_str(), false);

    if (ctx)
        ctx->indirect_resolved++;

    return 1;
}

//--------------------------------------------------------------------------
// Annotate unresolved indirect call
//--------------------------------------------------------------------------
void indirect_call_handler_t::annotate_indirect_call(mblock_t *blk, const indirect_call_t &ic) {
    if (!blk || !ic.call_insn)
        return;

    qstring comment;
    comment.sprnt("DEOBF: Indirect call (unresolved)");
    if (ic.table_addr != BADADDR) {
        comment.cat_sprnt("\n  Table: 0x%llX", (unsigned long long)ic.table_addr);
    }
    if (ic.table_index >= 0) {
        comment.cat_sprnt("\n  Index: %d", ic.table_index);
    }
    if (ic.offset != 0) {
        comment.cat_sprnt("\n  Offset: %lld", (long long)ic.offset);
    }

    set_cmt(ic.call_insn->ea, comment.c_str(), false);
}
