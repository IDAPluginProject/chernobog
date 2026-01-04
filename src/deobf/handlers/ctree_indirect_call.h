#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// CTree-level Indirect Call Resolution
//
// At ctree level, Hikari's IndirectCall pattern is clearly visible:
//   ((func_ptr)(table[index] - offset))(args...)
//
// We can match this pattern and replace with a direct call.
//--------------------------------------------------------------------------

// Detection only - doesn't modify at ctree level
class ctree_indirect_call_handler_t {
public:
    // Detect pattern at ctree level (called from hxe_maturity callback)
    static bool detect(cfunc_t *cfunc);
    
    // Run resolution (modifies cfunc)
    static int run(cfunc_t *cfunc, deobf_ctx_t *ctx);

private:
    // Check if expression is table[index] - offset pattern
    static bool match_pattern(cexpr_t *expr, ea_t *out_table, int64_t *out_index, int64_t *out_offset);
    
    // Read table entry and compute target
    static ea_t compute_call_target(ea_t table_addr, int64_t index, int64_t offset);
};
