#include "hikari_cfg.h"
#include "indirect_branch.h"
#include "../analysis/finite_targets.h"

#include "../analysis/arch_utils.h"
#include "../../common/arm64_branch.h"
#include "../../common/ida_memory.h"
#include "../../common/warn_off.h"
#include <fixup.hpp>
#include "../../common/warn_on.h"

#ifndef ALLINS_HPP_INCLUDED
#define ALLINS_HPP_INCLUDED
#include <allins.hpp>
#endif

#include <array>
#include <deque>
#include <limits>
#include <set>
#include <tuple>

namespace
{

constexpr size_t TAIL_WINDOW = 256;
constexpr uint32_t ARM64_NOP = 0xD503201FU;

struct state_slot_t
{
    int base_reg = -1;
    int64_t offset = 0;

    bool operator<(const state_slot_t &other) const
    {
        return std::tie(base_reg, offset) < std::tie(other.base_reg, other.offset);
    }
};

struct native_insn_t
{
    ea_t ea = BADADDR;
    insn_t insn;
};

struct dispatcher_proof_t
{
    ea_t function_ea = BADADDR;
    ea_t function_end = BADADDR;
    ea_t branch_ea = BADADDR;
    ea_t cset_ea = BADADDR;
    size_t cset_index = 0;
    int index_reg = -1;
    uint8_t condition = 0;
    ea_t table = BADADDR;
    int32_t bias = 0;
    uint32_t key = 0;
    std::array<ea_t, 2> targets = {BADADDR, BADADDR};
    std::vector<native_insn_t> tail;
};

using state_map_t = std::map<state_slot_t, ea_t>;
using immediate_map_t = std::map<int, std::set<uint32_t>>;

bool is_full_immediate_move(const insn_t &instruction)
{
    return (instruction.itype == ARM_mov || instruction.itype == ARM_movl) &&
           instruction.Op1.type == o_reg && instruction.Op2.type == o_imm;
}

void cfg_log(const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    deobf::debug_vlog("/tmp/chernobog_hikari_cfg.log", format, arguments);
    va_end(arguments);
}

void cfg_debug(ea_t function_ea, const char *reason)
{
    if (!deobf::debug_enabled())
        return;
    cfg_log("function=%a reject=%s\n", function_ea, reason);
}

bool is_changed_register(const insn_t &instruction, int *out)
{
    if (instruction.Op1.type != o_reg)
        return false;
    const uint32 feature = instruction.get_canon_feature(PH);
    if (!has_cf_chg(feature, 0))
        return false;
    if (out)
        *out = instruction.Op1.reg;
    return true;
}

std::vector<native_insn_t>
function_instructions(func_t *function, size_t retain_last = std::numeric_limits<size_t>::max())
{
    std::vector<native_insn_t> result;
    if (!function)
        return result;

    func_item_iterator_t iterator(function);
    for (bool ok = iterator.first(); ok; ok = iterator.next_code())
    {
        const ea_t ea = iterator.current();
        if (!is_code(get_flags(ea)))
            continue;
        native_insn_t item;
        item.ea = ea;
        if (decode_insn(&item.insn, ea) <= 0)
            continue;
        result.push_back(item);
        if (result.size() > retain_last)
            result.erase(result.begin());
    }
    return result;
}

bool is_state_base(int reg, int x19, int x29) { return reg == x19 || reg == x29; }

state_map_t collect_state_tables(func_t *function, int x19, int x29)
{
    state_map_t result;
    std::map<int, ea_t> register_constants;
    for (const native_insn_t &item : function_instructions(function))
    {
        const insn_t &instruction = item.insn;
        if ((instruction.itype == ARM_str || instruction.itype == ARM_stur) &&
            instruction.Op1.type == o_reg &&
            (instruction.Op2.type == o_displ || instruction.Op2.type == o_phrase))
        {
            const int source = instruction.Op1.reg;
            const int base = instruction.Op2.reg;
            const int64_t offset = static_cast<int64_t>(instruction.Op2.addr);
            const auto constant = register_constants.find(source);
            if (constant != register_constants.end() && is_state_base(base, x19, x29))
            {
                result[{base, offset}] = constant->second;
            }
        }
        else if (instruction.itype == ARM_stp && instruction.Op1.type == o_reg &&
                 instruction.Op2.type == o_reg &&
                 (instruction.Op3.type == o_displ || instruction.Op3.type == o_phrase))
        {
            const int base = instruction.Op3.reg;
            const int64_t offset = static_cast<int64_t>(instruction.Op3.addr);
            if (is_state_base(base, x19, x29))
            {
                const auto first = register_constants.find(instruction.Op1.reg);
                const auto second = register_constants.find(instruction.Op2.reg);
                if (first != register_constants.end())
                    result[{base, offset}] = first->second;
                if (second != register_constants.end())
                    result[{base, offset + 8}] = second->second;
            }
        }

        int changed = -1;
        if (is_changed_register(instruction, &changed))
            register_constants.erase(changed);
        if (instruction.itype == ARM_adrl && instruction.Op1.type == o_reg &&
            instruction.Op2.type == o_imm)
        {
            register_constants[instruction.Op1.reg] = static_cast<ea_t>(instruction.Op2.value);
        }
    }
    return result;
}

bool exact_function_entry(ea_t ea)
{
    const segment_t *segment = getseg(ea);
    const func_t *function = get_func(ea);
    return segment && (segment->perm & SEGPERM_EXEC) != 0 && function &&
           (function->flags & FUNC_TAIL) == 0 && function->start_ea == ea;
}

bool exact_fixup(ea_t ea)
{
    fixup_data_t fixup;
    return get_fixup(&fixup, ea) && !fixup.is_unused();
}

std::optional<std::tuple<int32_t, ea_t, ea_t, uint32_t>>
infer_targets(ea_t table, int key_reg, const std::optional<uint32_t> &local_key,
              const immediate_map_t &immediates, const std::vector<ea_t> &function_starts)
{
    const segment_t *segment = getseg(table);
    if (!segment || (segment->perm & SEGPERM_EXEC) != 0 || !exact_fixup(table) ||
        !exact_fixup(table + 8) || !is_loaded(table + 16))
    {
        return std::nullopt;
    }

    const std::optional<uint64_t> entry0 = chernobog::ida_memory::read_integer(table, 8);
    const std::optional<uint64_t> entry1 = chernobog::ida_memory::read_integer(table + 8, 8);
    const std::optional<uint64_t> encoded = chernobog::ida_memory::read_integer(table + 16, 4);
    if (!entry0 || !entry1 || !encoded)
        return std::nullopt;

    std::set<std::tuple<int32_t, ea_t, ea_t, uint32_t>> candidates;
    for (ea_t target0 : function_starts)
    {
        const int64_t wide_bias = static_cast<int64_t>(target0) - static_cast<int64_t>(*entry0);
        if (wide_bias < std::numeric_limits<int32_t>::min() ||
            wide_bias > std::numeric_limits<int32_t>::max())
        {
            continue;
        }
        const int32_t bias = static_cast<int32_t>(wide_bias);
        const ea_t target1 =
            static_cast<ea_t>(static_cast<uint64_t>(*entry1) + static_cast<int64_t>(bias));
        if (!exact_function_entry(target0) || !exact_function_entry(target1))
            continue;

        const uint32_t required_key =
            static_cast<uint32_t>(*encoded) ^ (uint32_t{0} - static_cast<uint32_t>(bias));
        bool key_matches = local_key && *local_key == required_key;
        if (!local_key)
        {
            const auto observed = immediates.find(key_reg);
            key_matches = observed != immediates.end() && observed->second.count(required_key) != 0;
        }
        if (key_matches)
            candidates.emplace(bias, target0, target1, required_key);
    }
    if (candidates.size() != 1)
    {
        if (deobf::debug_enabled())
        {
            cfg_log("infer table=%a candidates=%zu key_reg=%d local=%X\n", table, candidates.size(),
                    key_reg, local_key ? *local_key : uint32_t{0});
        }
        return std::nullopt;
    }
    return *candidates.begin();
}

int find_previous_definition(const std::vector<native_insn_t> &items, size_t before, int reg)
{
    for (size_t cursor = before; cursor > 0;)
    {
        --cursor;
        int changed = -1;
        if (is_changed_register(items[cursor].insn, &changed) && changed == reg)
        {
            return static_cast<int>(cursor);
        }
    }
    return -1;
}

std::optional<dispatcher_proof_t> analyze_dispatcher(func_t *function,
                                                     const state_map_t &state_tables,
                                                     const immediate_map_t &immediates,
                                                     const std::vector<ea_t> &function_starts)
{
    if (!function)
        return std::nullopt;
    std::vector<native_insn_t> items = function_instructions(function, TAIL_WINDOW);
    if (items.empty() || items.back().insn.itype != ARM_br || items.back().insn.Op1.type != o_reg)
    {
        return std::nullopt;
    }

    dispatcher_proof_t proof;
    proof.function_ea = function->start_ea;
    proof.function_end = function->end_ea;
    proof.branch_ea = items.back().ea;
    const int branch_reg = items.back().insn.Op1.reg;

    const int add_index = find_previous_definition(items, items.size() - 1, branch_reg);
    if (add_index < 0)
    {
        cfg_debug(function->start_ea, "no terminal ADD definition");
        return std::nullopt;
    }
    const native_insn_t &add = items[static_cast<size_t>(add_index)];
    const uint32_t add_word = get_dword(add.ea);
    if (add.insn.itype != ARM_add || add.insn.Op1.type != o_reg || add.insn.Op1.reg != branch_reg ||
        add.insn.Op2.type != o_reg || (add_word & 0xFFE0FC00U) != 0x8B20C000U)
    {
        cfg_debug(function->start_ea, "terminal ADD encoding mismatch");
        return std::nullopt;
    }
    const int entry_reg = add.insn.Op2.reg;
    qstring offset_name;
    offset_name.sprnt("X%d", static_cast<int>((add_word >> 16) & 0x1FU));
    const int offset_reg = str2reg(offset_name.c_str());
    if (offset_reg < 0)
    {
        cfg_debug(function->start_ea, "terminal ADD register decode failed");
        return std::nullopt;
    }

    const int neg_index =
        find_previous_definition(items, static_cast<size_t>(add_index), offset_reg);
    if (neg_index < 0)
    {
        cfg_debug(function->start_ea, "no bias NEG definition");
        return std::nullopt;
    }
    const insn_t &neg = items[static_cast<size_t>(neg_index)].insn;
    if (neg.itype != ARM_neg || neg.Op1.type != o_reg || neg.Op1.reg != offset_reg ||
        neg.Op2.type != o_reg)
    {
        cfg_debug(function->start_ea, "bias NEG encoding mismatch");
        return std::nullopt;
    }
    const int encoded_reg = neg.Op2.reg;

    const int eor_index =
        find_previous_definition(items, static_cast<size_t>(neg_index), encoded_reg);
    if (eor_index < 0)
    {
        cfg_debug(function->start_ea, "no bias EOR definition");
        return std::nullopt;
    }
    const insn_t &eor = items[static_cast<size_t>(eor_index)].insn;
    if (eor.itype != ARM_eor || eor.Op1.type != o_reg || eor.Op1.reg != encoded_reg ||
        eor.Op2.type != o_reg || eor.Op3.type != o_reg)
    {
        cfg_debug(function->start_ea, "bias EOR encoding mismatch");
        return std::nullopt;
    }
    int key_reg = -1;
    if (eor.Op2.reg == encoded_reg && eor.Op3.reg != encoded_reg)
        key_reg = eor.Op3.reg;
    else if (eor.Op3.reg == encoded_reg && eor.Op2.reg != encoded_reg)
        key_reg = eor.Op2.reg;
    if (key_reg < 0)
    {
        cfg_debug(function->start_ea, "bias EOR has no distinct key register");
        return std::nullopt;
    }

    std::optional<uint32_t> local_key;
    const int key_definition =
        find_previous_definition(items, static_cast<size_t>(eor_index), key_reg);
    if (key_definition >= 0)
    {
        const insn_t &definition = items[static_cast<size_t>(key_definition)].insn;
        if (is_full_immediate_move(definition))
            local_key = static_cast<uint32_t>(definition.Op2.value);
    }

    const int indexed_index =
        find_previous_definition(items, static_cast<size_t>(add_index), entry_reg);
    if (indexed_index < 0)
    {
        cfg_debug(function->start_ea, "no indexed LDR definition");
        return std::nullopt;
    }
    const native_insn_t &indexed = items[static_cast<size_t>(indexed_index)];
    const uint32_t indexed_word = get_dword(indexed.ea);
    if (indexed.insn.itype != ARM_ldr || indexed.insn.Op1.type != o_reg ||
        indexed.insn.Op1.reg != entry_reg || (indexed_word & 0xFFE0FC00U) != 0xF8605800U)
    {
        cfg_debug(function->start_ea, "indexed LDR encoding mismatch");
        return std::nullopt;
    }
    const int raw_index_reg = static_cast<int>((indexed_word >> 16) & 0x1FU);
    qstring index_name;
    index_name.sprnt("X%d", raw_index_reg);
    const int index_reg = str2reg(index_name.c_str());
    const int base_reg = indexed.insn.Op2.reg;
    if (index_reg < 0 || base_reg < 0)
    {
        cfg_debug(function->start_ea, "indexed LDR register decode failed");
        return std::nullopt;
    }

    const int base_definition =
        find_previous_definition(items, static_cast<size_t>(indexed_index), base_reg);
    if (base_definition < 0)
    {
        cfg_debug(function->start_ea, "no table base definition");
        return std::nullopt;
    }
    const insn_t &base = items[static_cast<size_t>(base_definition)].insn;
    if ((base.itype != ARM_ldr && base.itype != ARM_ldur) || base.Op1.type != o_reg ||
        base.Op1.reg != base_reg || (base.Op2.type != o_displ && base.Op2.type != o_phrase))
    {
        cfg_debug(function->start_ea, "table base load mismatch");
        return std::nullopt;
    }
    const state_slot_t slot = {
        base.Op2.reg,
        static_cast<int64_t>(base.Op2.addr),
    };
    const auto table = state_tables.find(slot);
    if (table == state_tables.end())
    {
        cfg_debug(function->start_ea, "table state slot absent from root map");
        return std::nullopt;
    }

    const int cset_index =
        find_previous_definition(items, static_cast<size_t>(indexed_index), index_reg);
    if (cset_index < 0)
    {
        cfg_debug(function->start_ea, "no CSET index definition");
        return std::nullopt;
    }
    const insn_t &cset = items[static_cast<size_t>(cset_index)].insn;
    if (cset.itype != ARM_cset || cset.Op1.type != o_reg || cset.Op1.reg != index_reg ||
        cset.Op2.value > 0xDU)
    {
        cfg_debug(function->start_ea, "CSET definition mismatch");
        return std::nullopt;
    }

    const auto targets =
        infer_targets(table->second, key_reg, local_key, immediates, function_starts);
    if (!targets)
    {
        if (deobf::debug_enabled())
        {
            cfg_log("function=%a detail table=%a key_reg=%d local_key=%llX "
                    "entry0=%llX entry1=%llX encoded=%X\n",
                    function->start_ea, table->second, key_reg,
                    static_cast<unsigned long long>(local_key ? *local_key : uint32_t{0}),
                    static_cast<unsigned long long>(get_qword(table->second)),
                    static_cast<unsigned long long>(get_qword(table->second + 8)),
                    get_dword(table->second + 16));
        }
        cfg_debug(function->start_ea, "target/key inference not unique");
        return std::nullopt;
    }
    proof.bias = std::get<0>(*targets);
    proof.targets = {std::get<1>(*targets), std::get<2>(*targets)};
    proof.key = std::get<3>(*targets);
    proof.table = table->second;
    proof.index_reg = index_reg;
    proof.condition = static_cast<uint8_t>(cset.Op2.value);
    proof.cset_index = static_cast<size_t>(cset_index);
    proof.cset_ea = items[proof.cset_index].ea;
    proof.tail = std::move(items);
    return proof;
}

const char *condition_name(uint8_t condition)
{
    static const char *names[] = {
        "EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE",
    };
    return condition < qnumber(names) ? names[condition] : "?";
}

void annotate_dispatcher(const dispatcher_proof_t &proof)
{
    add_cref(proof.branch_ea, proof.targets[0], fl_JN);
    add_cref(proof.branch_ea, proof.targets[1], fl_JN);
    qstring comment;
    comment.sprnt("DEOBF: Hikari two-way %s: false=%a, true=%a; table=%a, bias=%d",
                  condition_name(proof.condition), proof.targets[0], proof.targets[1], proof.table,
                  proof.bias);
    set_cmt(proof.branch_ea, comment.c_str(), false);
}

bool has_external_incoming_edge(ea_t ea, ea_t range_start, ea_t range_end)
{
    xrefblk_t xref;
    for (bool ok = xref.first_to(ea, XREF_FAR); ok; ok = xref.next_to())
    {
        if (xref.iscode && (xref.from < range_start || xref.from > range_end))
        {
            return true;
        }
    }
    return false;
}

// Instructions whose only effect is a register value. None of them updates
// NZCV, so the compare that produced the dispatch condition still describes
// the branch after the instruction is removed.
bool pure_dispatch_instruction(const insn_t &instruction)
{
    switch (instruction.itype)
    {
    case ARM_ldr:
    case ARM_ldur:
    case ARM_adr:
    case ARM_adrp:
    case ARM_adrl:
    case ARM_mov:
    case ARM_movl:
    case ARM_neg:
    case ARM_eor:
    case ARM_add:
    case ARM_sub:
    case ARM_and:
    case ARM_orr:
    case ARM_lsl:
    case ARM_lsr:
    case ARM_asr:
        return true;
    default:
        return false;
    }
}

bool is_dispatch_store(const insn_t &instruction)
{
    switch (instruction.itype)
    {
    case ARM_str:
    case ARM_stur:
    case ARM_stp:
    case ARM_stnp:
        return true;
    default:
        return false;
    }
}

bool is_pc_relative(const insn_t &instruction)
{
    if (instruction.itype == ARM_adr || instruction.itype == ARM_adrp ||
        instruction.itype == ARM_adrl)
    {
        return true;
    }
    return (instruction.itype == ARM_ldr || instruction.itype == ARM_ldur) &&
           instruction.Op2.type == o_imm;
}

// A PC-relative materialization names an address that can outlive the tail:
// Hikari blocks share hoisted global-address registers across their dispatch
// edges. Such an instruction is kept and re-encoded for its new slot rather
// than discarded with the rest of the target computation.
std::optional<uint32_t> relocate_pc_relative(const insn_t &instruction, ea_t site, ea_t new_site)
{
    if (instruction.Op1.type != o_reg)
        return std::nullopt;
    const uint32_t word = get_dword(site);
    // The low five bits are the architectural register field. IDA register
    // numbers are wider than that field, so re-encode from the raw word.
    const uint32_t rd = word & 0x1FU;
    if (instruction.itype == ARM_adrp || instruction.itype == ARM_adr)
    {
        int64_t immediate = (int64_t((word >> 5) & 0x7FFFFU) << 2) | ((word >> 29) & 3U);
        if ((immediate & (int64_t(1) << 20)) != 0)
            immediate -= int64_t(1) << 21;
        const bool page = instruction.itype == ARM_adrp;
        const ea_t base = page ? (site & ~ea_t(0xFFF)) : site;
        const int64_t target = int64_t(base) + (page ? (immediate << 12) : immediate);
        const ea_t new_base = page ? (new_site & ~ea_t(0xFFF)) : new_site;
        const int64_t delta = target - int64_t(new_base);
        if (page && (delta & 0xFFF) != 0)
            return std::nullopt;
        const int64_t scaled = page ? (delta >> 12) : delta;
        if (scaled < -(int64_t(1) << 20) || scaled >= (int64_t(1) << 20))
            return std::nullopt;
        const uint32_t immlo = uint32_t(scaled) & 3U;
        const uint32_t immhi = (uint32_t(scaled) >> 2) & 0x7FFFFU;
        const uint32_t opcode = page ? 0x90000000U : 0x10000000U;
        return opcode | (immlo << 29) | (immhi << 5) | rd;
    }
    if (instruction.itype == ARM_ldr && instruction.Op2.type == o_imm)
    {
        int64_t offset = (int64_t((word >> 5) & 0x7FFFFU) << 2) | ((word >> 29) & 3U);
        if ((offset & (int64_t(1) << 20)) != 0)
            offset -= int64_t(1) << 21;
        const int64_t delta = (int64_t(site) + offset) - int64_t(new_site);
        if ((delta & 3) != 0 || delta < -(int64_t(1) << 20) || delta >= (int64_t(1) << 20))
            return std::nullopt;
        return (word & ~0x00FFFFE0U) | ((uint32_t(delta >> 2) & 0x7FFFFU) << 5);
    }
    return std::nullopt;
}

void register_operands(const insn_t &instruction, std::vector<int> *changed, std::vector<int> *used)
{
    const uint32 feature = instruction.get_canon_feature(PH);
    for (int index = 0; index < UA_MAXOP; ++index)
    {
        const op_t &operand = instruction.ops[index];
        if (operand.type == o_void)
            break;
        const bool writes = has_cf_chg(feature, index);
        if (operand.type == o_reg)
        {
            if (writes)
            {
                if (changed)
                    changed->push_back(operand.reg);
            }
            else if (has_cf_use(feature, index) && used)
            {
                used->push_back(operand.reg);
            }
        }
        else if (operand.type == o_displ || operand.type == o_phrase)
        {
            // The base register is read even when the operand as a whole is
            // the written memory location.
            if (used)
                used->push_back(operand.reg);
        }
    }
}

// Walk the definitions that feed the indirect branch: the loaded table entry,
// the index, the keyed-bias arithmetic and the page holding the encoded bias.
// Only these instructions compute the dispatch target, so only these can be
// discarded once the target is a constant. Every other instruction in the tail
// may carry a value into the successor block; Hikari hoists such values across
// dispatch edges, so they are kept.
std::set<ea_t> target_chain(const dispatcher_proof_t &proof, size_t patch_index)
{
    std::set<ea_t> chain;
    std::vector<int> used;
    const size_t branch_index = proof.tail.size() - 1;
    register_operands(proof.tail[branch_index].insn, nullptr, &used);
    std::deque<std::pair<size_t, int>> work;
    for (int reg : used)
        work.emplace_back(branch_index, reg);
    while (!work.empty())
    {
        const auto [user, reg] = work.front();
        work.pop_front();
        const int definition = find_previous_definition(proof.tail, user, reg);
        if (definition < 0 || static_cast<size_t>(definition) < patch_index)
            continue;
        const native_insn_t &item = proof.tail[static_cast<size_t>(definition)];
        if (!chain.insert(item.ea).second)
            continue;
        std::vector<int> reads;
        register_operands(item.insn, nullptr, &reads);
        for (int read : reads)
            work.emplace_back(static_cast<size_t>(definition), read);
    }
    return chain;
}

// Stores and the pure dispatch instructions do not update NZCV. The compare
// that produced the dispatch condition can therefore sit further back than the
// instruction immediately before the index selection.
bool flag_neutral(const insn_t &instruction)
{
    return is_dispatch_store(instruction) || pure_dispatch_instruction(instruction);
}

bool has_reachable_compare(const dispatcher_proof_t &proof)
{
    for (size_t index = proof.cset_index; index > 0;)
    {
        --index;
        if (proof.tail[index].insn.itype == ARM_cmp)
            return true;
        if (!flag_neutral(proof.tail[index].insn))
            return false;
    }
    return false;
}

// The ARM decoder can fold an immediate move and its MOVK into a single
// eight-byte instruction, so a kept instruction does not always occupy one
// word of the slot.
size_t instruction_words(const native_insn_t &item)
{
    const size_t bytes = item.insn.size > 0 ? static_cast<size_t>(item.insn.size) : size_t(4);
    return std::max<size_t>(1, (bytes + 3) / 4);
}

bool patch_compact_dispatcher(const dispatcher_proof_t &proof)
{
    const auto branch = chernobog::arm64_branch::decode_indirect(get_dword(proof.branch_ea));
    if (!branch || branch->authenticated)
    {
        cfg_debug(proof.function_ea, "terminal branch is not a plain indirect branch");
        return false;
    }
    if (proof.cset_index == 0 || !has_reachable_compare(proof))
    {
        cfg_debug(proof.function_ea, "no reachable flag-setting compare before the index select");
        return false;
    }

    const size_t patch_index = proof.cset_index + 1;
    if (patch_index + 1 >= proof.tail.size())
    {
        cfg_debug(proof.function_ea, "no instruction follows the index select");
        return false;
    }

    const ea_t patch_start = proof.tail[patch_index].ea;
    const asize_t region_size = proof.branch_ea + 4 - patch_start;
    if (region_size < 12 || (region_size & 3U) != 0)
    {
        cfg_debug(proof.function_ea, "dispatch region is smaller than three instructions");
        return false;
    }

    // The tail between the index selection and the indirect branch mixes the
    // target computation with stores and hoisted values that also run on both
    // paths. Those are kept in their original order; only the target
    // computation is replaced, and the kept instructions must fit in front of
    // the three branch instructions.
    const size_t region_instructions = proof.tail.size() - 1 - patch_index;
    enum role_t
    {
        ROLE_DROP,
        ROLE_KEEP,
        ROLE_REJECT
    };
    std::vector<role_t> roles(region_instructions, ROLE_DROP);
    std::vector<std::vector<int>> uses(region_instructions);
    const std::set<ea_t> chain = target_chain(proof, patch_index);
    for (size_t index = 0; index < region_instructions; ++index)
    {
        const native_insn_t &item = proof.tail[patch_index + index];
        const insn_t &instruction = item.insn;
        if (is_dispatch_store(instruction))
        {
            // A phrase operand hides its index register from the operand list,
            // so the order-aware slice below cannot see that read.
            if (instruction.Op1.type == o_phrase || instruction.Op2.type == o_phrase ||
                instruction.Op3.type == o_phrase)
            {
                roles[index] = ROLE_REJECT;
                continue;
            }
            roles[index] = ROLE_KEEP;
            register_operands(instruction, nullptr, &uses[index]);
        }
        else if (is_pc_relative(instruction))
        {
            roles[index] = pure_dispatch_instruction(instruction) ? ROLE_KEEP : ROLE_REJECT;
        }
        else if (chain.count(item.ea) != 0)
        {
            roles[index] = ROLE_DROP;
        }
        else if (pure_dispatch_instruction(instruction))
        {
            roles[index] = ROLE_KEEP;
            register_operands(instruction, nullptr, &uses[index]);
        }
        else
        {
            roles[index] = ROLE_REJECT;
        }
    }
    for (size_t index = 0; index < region_instructions; ++index)
    {
        if (roles[index] == ROLE_REJECT)
        {
            qstring reason;
            reason.sprnt("tail instruction %a itype=%d is neither a store nor pure dispatch",
                         proof.tail[patch_index + index].ea,
                         proof.tail[patch_index + index].insn.itype);
            cfg_debug(proof.function_ea, reason.c_str());
            return false;
        }
        if (has_external_incoming_edge(proof.tail[patch_index + index].ea, proof.cset_ea,
                                       proof.branch_ea))
        {
            cfg_debug(proof.function_ea, "tail instruction has an external incoming edge");
            return false;
        }
    }

    // Promote a definition into the kept prefix when a kept store reads it.
    for (size_t pass = 0; pass <= region_instructions; ++pass)
    {
        bool changed = false;
        for (size_t index = 0; index < region_instructions; ++index)
        {
            if (roles[index] != ROLE_KEEP)
                continue;
            for (int reg : uses[index])
            {
                const int definition =
                    find_previous_definition(proof.tail, patch_index + index, reg);
                if (definition < static_cast<int>(patch_index))
                    continue;
                const size_t at = static_cast<size_t>(definition) - patch_index;
                if (roles[at] == ROLE_DROP)
                {
                    roles[at] = ROLE_KEEP;
                    register_operands(proof.tail[patch_index + at].insn, nullptr, &uses[at]);
                    changed = true;
                }
            }
        }
        if (!changed)
            break;
    }

    size_t kept_words = 0;
    for (size_t index = 0; index < region_instructions; ++index)
    {
        if (roles[index] == ROLE_KEEP)
            kept_words += instruction_words(proof.tail[patch_index + index]);
    }
    const size_t region_words = region_size / 4;
    if (kept_words + 3 > region_words)
    {
        cfg_debug(proof.function_ea, "tail has no room for the kept stores and branches");
        return false;
    }

    const ea_t condition_ea = patch_start + ea_t(kept_words * 4);
    const std::optional<uint32_t> conditional = chernobog::arm64_branch::encode_b_cond(
        condition_ea, condition_ea + 8, proof.condition ^ 1U);
    const std::optional<uint32_t> true_branch =
        chernobog::arm64_branch::encode_b(condition_ea + 4, proof.targets[1]);
    const std::optional<uint32_t> false_branch =
        chernobog::arm64_branch::encode_b(condition_ea + 8, proof.targets[0]);
    if (!conditional || !true_branch || !false_branch)
    {
        cfg_debug(proof.function_ea, "dispatch targets are out of branch range from the new slot");
        return false;
    }

    std::vector<uint32_t> emitted;
    emitted.reserve(region_words);
    for (size_t index = 0; index < region_instructions; ++index)
    {
        if (roles[index] != ROLE_KEEP)
            continue;
        const native_insn_t &kept = proof.tail[patch_index + index];
        const size_t words = instruction_words(kept);
        uint32_t first = get_dword(kept.ea);
        if (is_pc_relative(kept.insn))
        {
            const std::optional<uint32_t> relocated =
                relocate_pc_relative(kept.insn, kept.ea, patch_start + ea_t(emitted.size() * 4));
            if (!relocated)
            {
                cfg_debug(proof.function_ea, "kept PC-relative value cannot reach its new slot");
                return false;
            }
            if (deobf::debug_enabled())
            {
                cfg_log("relocate function=%a from=%a to=%a old=%08X new=%08X rd=%d\n",
                        proof.function_ea, kept.ea, patch_start + ea_t(emitted.size() * 4),
                        get_dword(kept.ea), *relocated, kept.insn.Op1.reg);
            }
            first = *relocated;
        }
        emitted.push_back(first);
        // The decoder folds an immediate move and its MOVK into one
        // instruction; every word of it must move to the new slot.
        for (size_t word = 1; word < words; ++word)
            emitted.push_back(get_dword(kept.ea + ea_t(word * 4)));
    }
    emitted.push_back(*conditional);
    emitted.push_back(*true_branch);
    emitted.push_back(*false_branch);

    if (!del_items(patch_start, DELIT_SIMPLE, region_size))
    {
        cfg_debug(proof.function_ea, "cannot undefine the dispatch region");
        return false;
    }
    for (ea_t ea = patch_start; ea <= proof.branch_ea; ea += 4)
        patch_dword(ea, ARM64_NOP);
    for (size_t index = 0; index < emitted.size(); ++index)
        patch_dword(patch_start + ea_t(index * 4), emitted[index]);
    for (ea_t ea = patch_start; ea <= proof.branch_ea;)
    {
        const int size = create_insn(ea);
        if (size <= 0)
        {
            cfg_debug(proof.function_ea, "cannot recreate the rewritten instructions");
            return false;
        }
        ea += ea_t(size);
    }
    if (!set_func_end(proof.function_ea, proof.function_end))
    {
        cfg_debug(proof.function_ea, "cannot restore the function end");
        return false;
    }

    add_cref(condition_ea, condition_ea + 8, fl_JN);
    add_cref(condition_ea + 4, proof.targets[1], fl_JN);
    add_cref(condition_ea + 8, proof.targets[0], fl_JN);
    qstring comment;
    comment.sprnt("DEOBF: reversible Hikari dispatch rewrite; %s->%a, else->%a",
                  condition_name(proof.condition), proof.targets[1], proof.targets[0]);
    set_cmt(condition_ea, comment.c_str(), false);
    plan_range(patch_start, proof.branch_ea + 4);
    if (deobf::debug_enabled())
    {
        cfg_log("patch function=%a start=%a words=%zu region=%zu condition=%s "
                "table=%a target0=%a target1=%a\n",
                proof.function_ea, patch_start, emitted.size(), region_words,
                condition_name(proof.condition), proof.table, proof.targets[0], proof.targets[1]);
    }
    return true;
}

std::optional<std::array<ea_t, 2>> recover_table_dispatcher(func_t *function)
{
    // This fallback admits the actual target expression, not a particular
    // ADD/NEG/EOR instruction template. It is bounded separately from the
    // inexpensive native recognizer and never patches authentication away.
    static bool active = false;
    if (active || !function || function->end_ea - function->start_ea > 4096)
        return std::nullopt;
    const auto items = function_instructions(function, TAIL_WINDOW);
    if (items.empty() || items.back().insn.itype != ARM_br ||
        std::none_of(items.begin(), items.end(),
                     [](const native_insn_t &item) { return item.insn.itype == ARM_cset; }))
        return std::nullopt;
    struct Guard
    {
        Guard() { active = true; }
        ~Guard() { active = false; }
    } guard;
    hexrays_failure_t failure;
    std::unique_ptr<mba_t> mba(gen_microcode(mba_ranges_t(function), &failure, nullptr,
                                             DECOMP_NO_CACHE | DECOMP_NO_WAIT, MMAT_GLBOPT3));
    if (!mba)
        return std::nullopt;
    for (int index = 0; index < mba->qty; ++index)
    {
        mblock_t *block = mba->get_mblock(index);
        minsn_t *tail = block->tail;
        if (!tail || tail->opcode != m_ijmp)
            continue;
        const auto finite = chernobog::evaluate_finite_targets(tail->d, tail, block);
        if (!finite || finite->targets.size() != 2 || finite->condition.empty())
            continue;
        deobf_ctx_t context;
        context.mba = mba.get();
        context.func_ea = function->start_ea;
        indirect_branch_handler_t::run(mba.get(), &context);
        return finite->targets_by_condition;
    }
    return std::nullopt;
}

} // namespace

int hikari_cfg_handler_t::mode()
{
    qstring value;
    if (!qgetenv("CHERNOBOG_HIKARI_CFG", &value) || value.empty())
        return 0;
    if (value[0] == '2')
        return 2;
    if (value[0] == '1')
        return 1;
    return 0;
}

hikari_cfg_stats_t hikari_cfg_handler_t::run()
{
    hikari_cfg_stats_t stats;
    const int recovery_mode = mode();
    if (recovery_mode == 0 || !arch::is_arm64())
        return stats;

    const int x19 = str2reg("X19");
    const int x29 = str2reg("X29");
    if (x19 < 0 || x29 < 0)
        return stats;

    std::vector<ea_t> function_starts;
    immediate_map_t immediates;
    func_t *root = nullptr;
    state_map_t root_tables;
    bool root_ambiguous = false;
    const size_t function_count = get_func_qty();
    for (size_t index = 0; index < function_count; ++index)
    {
        func_t *function = getn_func(index);
        if (!function || (function->flags & FUNC_TAIL) != 0)
            continue;
        function_starts.push_back(function->start_ea);

        for (const native_insn_t &item : function_instructions(function))
        {
            const insn_t &instruction = item.insn;
            if (is_full_immediate_move(instruction))
            {
                immediates[instruction.Op1.reg].insert(
                    static_cast<uint32_t>(instruction.Op2.value));
            }
        }

        const state_map_t candidate = collect_state_tables(function, x19, x29);
        if (candidate.size() > root_tables.size())
        {
            root = function;
            root_tables = candidate;
            root_ambiguous = false;
        }
        else if (!candidate.empty() && candidate.size() == root_tables.size())
        {
            root_ambiguous = true;
        }
    }
    stats.root_state_slots = static_cast<int>(root_tables.size());
    const bool legacy_root = root && root_tables.size() >= 4 && !root_ambiguous;
    if (!legacy_root)
        deobf::log("[hikari_cfg] No unique root state-table initializer found\n");
    const ea_t root_ea = legacy_root ? root->start_ea : BADADDR;

    std::vector<dispatcher_proof_t> proofs;
    for (ea_t function_ea : function_starts)
    {
        func_t *function = get_func(function_ea);
        if (!function)
            continue;
        const std::vector<native_insn_t> tail = function_instructions(function, 1);
        if (!tail.empty() && tail.back().insn.itype == ARM_br)
            ++stats.terminal_indirect_branches;

        const auto proof =
            legacy_root ? analyze_dispatcher(function, root_tables, immediates, function_starts)
                        : std::nullopt;
        if (proof)
            proofs.push_back(*proof);
    }
    stats.recovered_dispatchers = static_cast<int>(proofs.size());

    std::map<ea_t, std::array<ea_t, 2>> graph;
    for (const dispatcher_proof_t &proof : proofs)
    {
        graph[proof.function_ea] = proof.targets;
        annotate_dispatcher(proof);
        if (recovery_mode >= 2 && patch_compact_dispatcher(proof))
            ++stats.patched_dispatchers;
    }

    size_t generic_attempts = 0;
    for (ea_t function_ea : function_starts)
    {
        if (graph.count(function_ea) != 0)
            continue;
        func_t *function = get_func(function_ea);
        const auto tail = function_instructions(function, TAIL_WINDOW);
        if (tail.empty() || tail.back().insn.itype != ARM_br ||
            std::none_of(tail.begin(), tail.end(),
                         [](const native_insn_t &item) { return item.insn.itype == ARM_cset; }))
            continue;
        if (++generic_attempts > 64)
            break;
        if (const auto targets = recover_table_dispatcher(function))
        {
            graph[function_ea] = *targets;
            ++stats.recovered_dispatchers;
        }
    }

    std::set<ea_t> reachable;
    std::deque<ea_t> queue;
    if (root_ea != BADADDR)
    {
        reachable.insert(root_ea);
        queue.push_back(root_ea);
    }
    while (!queue.empty())
    {
        const ea_t source = queue.front();
        queue.pop_front();
        const auto edges = graph.find(source);
        if (edges == graph.end())
            continue;
        for (ea_t target : edges->second)
        {
            if (reachable.insert(target).second)
                queue.push_back(target);
        }
    }
    stats.reachable_functions = static_cast<int>(reachable.size());
    deobf::log("[hikari_cfg] root=%a slots=%d indirect=%d recovered=%d "
               "patched=%d reachable=%d\n",
               root_ea, stats.root_state_slots, stats.terminal_indirect_branches,
               stats.recovered_dispatchers, stats.patched_dispatchers, stats.reachable_functions);
    return stats;
}
