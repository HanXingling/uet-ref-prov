#!/usr/bin/env python3

"""
Copyright (c) 2025, Broadcom. All rights reserved. The term
Broadcom refers to Broadcom Limited and/or its subsidiaries.

100% vibe coded with zero documentation, spaghetti logic, infinite edge
cases, maximum confidence, and love (w/ a cookie on the side).

Generate Mermaid packet diagrams from the C structures in 'uet_pkt_hdr.h'.

% python3 generate_packet_diagrams.py -h
% python3 generate_packet_diagrams.py --input uet_pkt_hdr.h --generate-images

Requires 'mermaid-cli' (i.e., mmdc) to be installed for image generation.
"""

import re
import sys
import argparse
import subprocess
import tempfile
import os
from typing import List, Tuple, Optional
from dataclasses import dataclass, field

@dataclass
class Field:
    """Represents a field in a C structure"""
    name: str
    type: str
    bit_width: int
    is_array: bool = False
    array_size: Optional[str] = None

@dataclass
class BitField:
    """Represents a bit field within a larger field"""
    name: str
    start_bit: int
    end_bit: int
    mask: int
    shift: int

@dataclass
class Struct:
    """Represents a C structure"""
    name: str
    fields: List[Field]
    is_packed: bool = False
    bit_fields: dict = field(default_factory=dict)  # Maps field name to list of BitField
    nested_flags: dict = field(default_factory=dict)  # Maps nested struct field name to flag BitFields

# Global cache of field bit field definitions (shared across structures)
FIELD_BITFIELD_CACHE = {}

# Type to bit width mapping
TYPE_SIZES = {
    'uint8_t': 8,
    'int8_t': 8,
    'uint16_t': 16,
    'int16_t': 16,
    'uint32_t': 32,
    'int32_t': 32,
    'uint64_t': 64,
    'int64_t': 64,
}

def parse_field_type(field_decl: str) -> Tuple[str, str, bool, Optional[str]]:
    """
    Parse a field declaration and extract type, name, array info.
    Returns: (type, name, is_array, array_size)
    """
    # Remove leading/trailing whitespace
    field_decl = field_decl.strip()

    # Check for array
    array_match = re.search(r'(\w+)\s+(\w+)\[([^\]]+)\]', field_decl)
    if array_match:
        return array_match.group(1), array_match.group(2), True, array_match.group(3)

    # Regular field
    parts = field_decl.split()
    if len(parts) >= 2:
        type_name = parts[0]
        var_name = parts[1].rstrip(';')
        return type_name, var_name, False, None

    return '', '', False, None

def extract_structs(file_content: str) -> dict:
    """Extract all packed structures from the header file"""
    structs = {}

    # First, collect all global #define statements from the entire file
    global_defines = {}
    define_pattern = re.compile(r'#define\s+(\w+)\s+(.+?)(?:\s*/\*.*?\*/)?$', re.MULTILINE)
    for match in define_pattern.finditer(file_content):
        name = match.group(1)
        value = match.group(2).strip()
        global_defines[name] = value

    # Find all struct definitions by matching braces properly
    # Pattern to find struct keyword and name
    struct_starts = list(re.finditer(r'struct\s+(?:UET_PACKED\s+)?(\w+)\s*\{', file_content))

    for match in struct_starts:
        struct_name = match.group(1)
        start_pos = match.end()  # Position right after opening brace

        # Skip if this is just a typedef, vlan tag, or UET_PACKED (anonymous struct)
        if struct_name in ['uet_vlan_tag', 'UET_PACKED']:
            continue

        # Find matching closing brace
        brace_count = 1
        pos = start_pos
        while pos < len(file_content) and brace_count > 0:
            if file_content[pos] == '{':
                brace_count += 1
            elif file_content[pos] == '}':
                brace_count -= 1
            pos += 1

        if brace_count == 0:
            struct_body = file_content[start_pos:pos-1]

            # Check if it's packed
            is_packed = 'UET_PACKED' in match.group(0)

            fields, field_bit_fields, nested_flags = parse_struct_body(struct_body, struct_name, global_defines)

            # Update global cache with new bit field definitions
            for field_name, bitfields in field_bit_fields.items():
                FIELD_BITFIELD_CACHE[field_name] = bitfields

            if fields:  # Only add if we successfully parsed fields
                structs[struct_name] = Struct(
                    name=struct_name,
                    fields=fields,
                    is_packed=is_packed,
                    bit_fields=field_bit_fields,
                    nested_flags=nested_flags
                )

    return structs

def parse_bit_field_defines_for_field(defines_text: str, all_defines: dict, field_name: str) -> List[BitField]:
    """
    Parse #define statements that appear before a field declaration.
    Returns a list of BitField objects for that specific field.
    Only includes defines that are actually mentioned in the defines_text.
    """
    bit_fields = []

    # Find which defines are actually in the defines_text
    defines_in_text = set()
    for line in defines_text.split('\n'):
        define_match = re.match(r'#define\s+(\w+)', line)
        if define_match:
            defines_in_text.add(define_match.group(1))

    # Find MASK/SHIFT pairs, but only if they appear in defines_text
    mask_defines = {k: v for k, v in all_defines.items()
                    if k.endswith('_MASK') and k in defines_in_text}

    for mask_name, mask_value in mask_defines.items():
        # Get the base name (remove _MASK suffix)
        base_name = mask_name[:-5]
        shift_name = base_name + '_SHIFT'

        # Check if we have a corresponding SHIFT (and it's also in the defines_text)
        if shift_name not in all_defines or shift_name not in defines_in_text:
            continue

        # Parse the mask value
        mask_int = parse_int_value(mask_value, all_defines)
        shift_int = parse_int_value(all_defines[shift_name], all_defines)

        if mask_int is None or shift_int is None:
            continue

        # Calculate bit positions
        num_bits = bin(mask_int).count('1')
        start_bit = shift_int
        end_bit = start_bit + num_bits - 1

        # Extract a friendly name from the define name
        friendly_name = base_name
        # Remove UET protocol prefixes
        for prefix in ['UET_PDS_', 'UET_SES_', 'UET_SEC_', 'UET_']:
            if friendly_name.startswith(prefix):
                friendly_name = friendly_name[len(prefix):]
                break

        # Remove SES-specific verbose prefixes
        for prefix in ['SES_DEF_RSP_', 'SES_DEF_', 'SES_RNDV_EXT_', 'SES_ATOMIC_EXT_', 'SES_ATOMIC_CMPSWP_EXT_',
                       'SES_REQ_CMN_', 'SES_REQ_STD_', 'SES_RSP_CMN_']:
            if friendly_name.startswith(prefix):
                friendly_name = friendly_name[len(prefix):]
                break

        # Remove REQ_/RSP_ prefixes from SES structures (e.g., RSP_LIST -> LIST, REQ_LEN -> LEN)
        for prefix in ['RSP_', 'REQ_']:
            if friendly_name.startswith(prefix):
                friendly_name = friendly_name[len(prefix):]
                break

        # Handle compound structure-specific prefixes (e.g., ACK_CC_TYPE -> CC_TYPE)
        # Replace ACK_CC_ with CC_, ACK_CCX_ with CCX_
        if friendly_name.startswith('ACK_CC_'):
            friendly_name = 'CC_' + friendly_name[len('ACK_CC_'):]
        elif friendly_name.startswith('ACK_CCX_'):
            friendly_name = 'CCX_' + friendly_name[len('ACK_CCX_'):]
        # Special handling for NACK_CCX fields
        elif friendly_name.startswith('NACK_CCX_'):
            # NACK_CCX_NCCX_TYPE -> NACK_CCX_TYPE (remove NCCX_ redundancy)
            # NACK_CCX_NACK_CCX_STATE1 -> NACK_CCX_STATE1 (remove NACK_CCX_ redundancy)
            rest = friendly_name[len('NACK_CCX_'):]
            if rest.startswith('NCCX_'):
                friendly_name = 'NACK_CCX_' + rest[len('NCCX_'):]
            elif rest.startswith('NACK_CCX_'):
                friendly_name = 'NACK_CCX_' + rest[len('NACK_CCX_'):]
        # For other prefixes, remove them unless it's a type/hdr field
        elif not friendly_name.endswith('_TYPE') and not friendly_name.endswith('_HDR'):
            for prefix in ['CTRL_', 'REQ_', 'ACK_', 'NACK_', 'RUDI_', 'UUD_']:
                if friendly_name.startswith(prefix):
                    friendly_name = friendly_name[len(prefix):]
                    break

        # Convert to lowercase (keep underscores)
        friendly_name = friendly_name.lower()

        # Special case: rename psn_offset to pdc_offset in ctrl context for clarity
        if friendly_name == 'psn_offset':
            friendly_name = 'pdc_offset'

        bit_field = BitField(
            name=friendly_name,
            start_bit=start_bit,
            end_bit=end_bit,
            mask=mask_int,
            shift=shift_int
        )

        bit_fields.append(bit_field)

    # Check for common global defines based on field name patterns
    # This handles cases where fields like "list_opcode" or "ver_flags" reference global defines
    # Exclude fields that should be treated as full-width (e.g., atomic_opcode is full 8 bits)
    global_patterns = []
    if 'opcode' in field_name.lower() and field_name.lower() not in ['atomic_opcode']:
        global_patterns.append('UET_SES_OPCODE')
    if field_name.lower().startswith('ver_') or '_ver_' in field_name.lower():
        global_patterns.append('UET_SES_VER')

    for pattern in global_patterns:
        mask_name = pattern + '_MASK'
        shift_name = pattern + '_SHIFT'

        # Only add if not already in local defines and exists in global defines
        if mask_name in all_defines and mask_name not in defines_in_text:
            mask_int = parse_int_value(all_defines[mask_name], all_defines)
            shift_int = parse_int_value(all_defines.get(shift_name, '0'), all_defines)

            if mask_int is not None and shift_int is not None:
                num_bits = bin(mask_int).count('1')
                start_bit = shift_int
                end_bit = start_bit + num_bits - 1

                # Check if these bit positions are already covered by existing bit fields
                overlaps = False
                for existing_bf in bit_fields:
                    # Check if the ranges overlap
                    if not (end_bit < existing_bf.start_bit or start_bit > existing_bf.end_bit):
                        overlaps = True
                        break

                if not overlaps:
                    # Extract friendly name from pattern
                    friendly_name = pattern.replace('UET_SES_', '').lower()

                    bit_field = BitField(
                        name=friendly_name,
                        start_bit=start_bit,
                        end_bit=end_bit,
                        mask=mask_int,
                        shift=shift_int
                    )

                    bit_fields.append(bit_field)

    return bit_fields

def parse_flag_defines(defines_text: str, all_defines: dict) -> List[BitField]:
    """
    Parse flag-style #define statements (e.g., UET_PDS_REQ_FLAGS_RETX 0x10).
    These are single mask values, not MASK/SHIFT pairs.
    Returns a list of BitField objects representing individual flag bits.
    """
    flag_fields = []

    # Find defines in the text that match *FLAG(S)?_* pattern (both FLAG_ and FLAGS_)
    for line in defines_text.split('\n'):
        match = re.match(r'#define\s+(\w*FLAGS?_\w+)\s+(\S+)', line)
        if not match:
            continue

        flag_name = match.group(1)
        flag_value = match.group(2)

        # Skip _NONE and _MASK and _SHIFT variants
        if flag_name.endswith('_NONE') or flag_name.endswith('_MASK') or flag_name.endswith('_SHIFT'):
            continue

        # Parse the mask value
        mask_int = parse_int_value(flag_value, all_defines)
        if mask_int is None or mask_int == 0:
            continue

        # Convert mask to bit positions
        # Find the lowest and highest bit set
        bit_pos = []
        for i in range(16):  # Assuming 16-bit max for flags
            if mask_int & (1 << i):
                bit_pos.append(i)

        if not bit_pos:
            continue

        start_bit = min(bit_pos)
        end_bit = max(bit_pos)

        # Extract a friendly name from the define name
        # Remove FLAG(S)_ and any prefix
        friendly_name = flag_name
        # Remove UET_PDS_*_FLAGS?_ or UET_SES_*_FLAGS?_ prefix
        friendly_name = re.sub(r'UET_[A-Z]+_[A-Z]+_FLAGS?_', '', friendly_name)
        friendly_name = re.sub(r'UET_[A-Z]+_FLAGS?_', '', friendly_name)

        # Special case for RSV (reserved)
        if friendly_name.startswith('RSV'):
            friendly_name = 'rsv'
        else:
            friendly_name = friendly_name.lower()

        flag_field = BitField(
            name=friendly_name,
            start_bit=start_bit,
            end_bit=end_bit,
            mask=mask_int,
            shift=start_bit
        )

        flag_fields.append(flag_field)

    return flag_fields

def parse_int_value(value: str, defines: dict) -> Optional[int]:
    """Parse an integer value from a #define, handling hex, references, etc."""
    value = value.strip()

    # Check if it references another define
    if value in defines:
        return parse_int_value(defines[value], defines)

    # Strip C-style integer suffixes (ULL, UL, LL, L, U)
    # Do this case-insensitively
    for suffix in ['ULL', 'ull', 'UL', 'ul', 'LL', 'll', 'L', 'l', 'U', 'u']:
        if value.endswith(suffix):
            value = value[:-len(suffix)]
            break

    # Try to parse as hex
    if value.startswith('0x') or value.startswith('0X'):
        try:
            return int(value, 16)
        except ValueError:
            return None

    # Try to parse as decimal
    try:
        return int(value, 10)
    except ValueError:
        return None

def parse_struct_body(body: str, struct_name: str, global_defines: dict = None) -> Tuple[List[Field], dict, dict]:
    """Parse the body of a structure and extract fields"""
    fields = []
    field_bit_fields = {}  # Map field name to its bit fields
    nested_flags = {}  # Map nested struct field name to flag bit fields

    # First, collect all #define statements from the struct body
    define_pattern = re.compile(r'#define\s+(\w+)\s+(.+?)(?:\s*/\*.*?\*/)?$', re.MULTILINE)
    local_defines = {}
    for match in define_pattern.finditer(body):
        name = match.group(1)
        value = match.group(2).strip()
        local_defines[name] = value

    # Merge global defines with local defines (local takes precedence)
    all_defines = {}
    if global_defines:
        all_defines.update(global_defines)
    all_defines.update(local_defines)

    # Now parse the body line by line, associating #defines with the fields that follow
    # Remove comments (preserve newlines for better parsing)
    body_no_comments = re.sub(r'/\*.*?\*/', '', body, flags=re.DOTALL)
    body_no_comments = re.sub(r'//.*$', '', body_no_comments, flags=re.MULTILINE)

    # Split by lines and process sequentially
    lines = body_no_comments.split('\n')
    current_defines = []  # Accumulate defines before a field

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Track #define statements
        if line.startswith('#define'):
            current_defines.append(line)
            continue

        # When we hit a field declaration, associate accumulated defines with it
        # Check if this line contains a field type
        field_match = None
        for type_name in TYPE_SIZES.keys():
            if type_name in line and ';' in line:
                field_match = line
                break

        # Also check for nested struct declarations
        nested_struct_match = None
        if 'struct' in line and ';' in line and 'UET_PACKED' not in line:
            nested_struct_match = re.search(r'struct\s+(\w+)\s+(\w+)', line)

        if field_match:
            # Parse the field
            parts = field_match.replace(';', '').split()
            if len(parts) >= 2:
                field_type = parts[0]
                field_name = parts[1]

                # Parse bit field defines for this field (even if current_defines is empty,
                # global pattern matching may apply)
                if field_type in TYPE_SIZES:
                    defines_text = '\n'.join(current_defines) if current_defines else ''

                    # First, try to parse MASK/SHIFT pairs and global patterns
                    bit_fields = parse_bit_field_defines_for_field(defines_text, all_defines, field_name)

                    # Then, check for flag-style defines and merge them
                    if current_defines and 'FLAG' in defines_text:
                        flag_fields = parse_flag_defines(defines_text, all_defines)
                        if flag_fields:
                            # Merge flag fields with bit fields, avoiding duplicates
                            existing_positions = set()
                            for bf in bit_fields:
                                for bit in range(bf.start_bit, bf.end_bit + 1):
                                    existing_positions.add(bit)

                            for ff in flag_fields:
                                # Only add if not overlapping with existing bit fields
                                overlaps = False
                                for bit in range(ff.start_bit, ff.end_bit + 1):
                                    if bit in existing_positions:
                                        overlaps = True
                                        break
                                if not overlaps:
                                    bit_fields.append(ff)

                    if bit_fields:
                        field_bit_fields[field_name] = bit_fields

                current_defines = []  # Reset for next field

        elif nested_struct_match:
            # This is a nested struct field - check for flag defines
            var_name = nested_struct_match.group(2)

            if current_defines:
                # Check if these are flag-style defines
                defines_text = '\n'.join(current_defines)
                if 'FLAGS_' in defines_text:
                    flag_fields = parse_flag_defines(defines_text, all_defines)
                    if flag_fields:
                        nested_flags[var_name] = flag_fields

            current_defines = []  # Reset for next field

    # Now parse fields normally (reuse existing logic)
    # Remove #define statements for field parsing
    body = re.sub(r'#define.*$', '', body_no_comments, flags=re.MULTILINE)

    # Track if we're in a union
    in_union = False
    union_depth = 0
    union_fields = []

    # Split more carefully - look for field terminators
    # We need to handle both ';' and '};' (end of union)
    lines = re.split(r';', body)

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Check for union start (including anonymous unions)
        if re.search(r'\bunion\s*\{', line):
            in_union = True
            union_depth += line.count('{')
            union_depth -= line.count('}')
            union_fields = []

            # Check if there's a field on the same line as union declaration
            # Extract the part after 'union {'
            after_union = re.split(r'\bunion\s*\{', line, maxsplit=1)
            if len(after_union) > 1:
                field_part = after_union[1].strip()
                # Check if it has a type declaration
                if any(t in field_part for t in TYPE_SIZES.keys()):
                    type_name, var_name, is_array, array_size = parse_field_type(field_part)
                    if type_name in TYPE_SIZES and var_name:
                        union_fields.append(Field(
                            name=var_name,
                            type=type_name,
                            bit_width=TYPE_SIZES[type_name],
                            is_array=is_array,
                            array_size=array_size
                        ))

            # Check if union closes on same line
            if union_depth == 0:
                in_union = False
                # Add the largest field from the union
                if union_fields:
                    # If the FIRST union member has bit fields, copy them to ALL union members
                    # This handles the case where #defines appear before the union (not inside it)
                    # We only copy from the first member because that's where pre-union defines go
                    # IMPORTANT: Do this BEFORE modifying field names!
                    if union_fields and union_fields[0].name in field_bit_fields:
                        union_bitfields = field_bit_fields[union_fields[0].name]
                        for uf in union_fields[1:]:  # Skip first, copy to rest
                            if uf.name not in field_bit_fields:
                                field_bit_fields[uf.name] = union_bitfields

                    # Now create the combined field
                    largest = max(union_fields, key=lambda f: f.bit_width if f.bit_width > 0 else 16)
                    union_names = ' | '.join(f.name for f in union_fields)
                    largest.name = f"[{union_names}]"
                    fields.append(largest)

                    union_fields = []
            continue

        # Track union depth
        if in_union:
            # Count braces to track nesting
            union_depth += line.count('{')
            union_depth -= line.count('}')

            # Parse union fields (before checking if union ends)
            if any(t in line for t in TYPE_SIZES.keys()):
                type_name, var_name, is_array, array_size = parse_field_type(line)
                if type_name in TYPE_SIZES and var_name:
                    union_fields.append(Field(
                        name=var_name,
                        type=type_name,
                        bit_width=TYPE_SIZES[type_name],
                        is_array=is_array,
                        array_size=array_size
                    ))
            # Check for nested struct in union
            elif 'struct' in line:
                struct_match = re.search(r'struct\s+(\w+)\s+(\w+)', line)
                if struct_match:
                    nested_struct_name = struct_match.group(1)
                    var_name = struct_match.group(2)
                    union_fields.append(Field(
                        name=var_name,
                        type=nested_struct_name,
                        bit_width=0,  # Will be calculated later
                    ))

            # Check if union is complete
            if union_depth == 0:
                in_union = False
                # Add the largest field from the union
                if union_fields:
                    # If the FIRST union member has bit fields, copy them to ALL union members
                    # This handles the case where #defines appear before the union (not inside it)
                    # We only copy from the first member because that's where pre-union defines go
                    # IMPORTANT: Do this BEFORE modifying field names!
                    if union_fields and union_fields[0].name in field_bit_fields:
                        union_bitfields = field_bit_fields[union_fields[0].name]
                        for uf in union_fields[1:]:  # Skip first, copy to rest
                            if uf.name not in field_bit_fields:
                                field_bit_fields[uf.name] = union_bitfields

                    # Now create the combined field
                    # Find the field with the largest bit width
                    largest = max(union_fields, key=lambda f: f.bit_width if f.bit_width > 0 else 16)
                    # Use a combined name to indicate it's a union
                    union_names = ' | '.join(f.name for f in union_fields)
                    largest.name = f"[{union_names}]"
                    fields.append(largest)

                    union_fields = []
            continue

        # Regular field
        if any(t in line for t in TYPE_SIZES.keys()):
            type_name, var_name, is_array, array_size = parse_field_type(line)
            if type_name in TYPE_SIZES and var_name:
                bit_width = TYPE_SIZES[type_name]
                fields.append(Field(
                    name=var_name,
                    type=type_name,
                    bit_width=bit_width,
                    is_array=is_array,
                    array_size=array_size
                ))

        # Check for nested struct
        elif 'struct' in line and 'UET_PACKED' not in line:
            # Extract the struct type and variable name
            struct_match = re.search(r'struct\s+(\w+)\s+(\w+)', line)
            if struct_match:
                nested_struct_name = struct_match.group(1)
                var_name = struct_match.group(2)
                # Add as a special field (we'll calculate size later)
                fields.append(Field(
                    name=var_name,
                    type=nested_struct_name,
                    bit_width=0  # Will be calculated when we have all structs
                ))

    return fields, field_bit_fields, nested_flags

def calculate_struct_sizes(structs: dict) -> dict:
    """Calculate the bit sizes of all structures (to handle nested structs)"""
    struct_sizes = {}

    # Multiple passes to handle nested dependencies
    max_iterations = 10
    for _ in range(max_iterations):
        changed = False
        for struct_name, struct in structs.items():
            if struct_name in struct_sizes:
                continue

            total_bits = 0
            can_calculate = True

            for field in struct.fields:
                if field.bit_width > 0:
                    total_bits += field.bit_width
                elif field.type in struct_sizes:
                    total_bits += struct_sizes[field.type]
                elif field.type in structs:
                    # Can't calculate yet, need nested struct size
                    can_calculate = False
                    break
                else:
                    # Unknown type, skip
                    can_calculate = False
                    break

            if can_calculate:
                struct_sizes[struct_name] = total_bits
                changed = True

        if not changed:
            break

    return struct_sizes

def generate_mermaid_diagrams(struct: Struct, all_structs: dict, struct_sizes: dict) -> List[str]:
    """
    Generate mermaid packet diagrams for a structure.
    Returns a list of diagrams - one for each union variant if unions exist.
    """
    # Special handling for uet_pds_ctrl
    if struct.name == 'uet_pds_ctrl':
        # Generate exactly three variants:
        # 1. CTRL_TYPE_PROBE: probe_opaque + dpdcid
        # 2. Other CTRL_TYPE with SYN=0: rsvd + dpdcid
        # 3. Other CTRL_TYPE with SYN=1: rsvd + pdc_info_psn_offset (broken down)

        diagrams = []

        # Find the union field names
        union_fields = []
        for field in struct.fields:
            if '[' in field.name and '|' in field.name:
                union_match = re.search(r'\[([^\]]+)\]', field.name)
                if union_match:
                    alternatives = [alt.strip() for alt in union_match.group(1).split('|')]
                    union_fields.append({
                        'field_name': field.name,
                        'alternatives': alternatives
                    })

        # Should have two unions
        if len(union_fields) >= 2:
            first_union = union_fields[0]['field_name']
            second_union = union_fields[1]['field_name']

            # Variant 1: CTRL_TYPE_PROBE (probe_opaque + dpdcid)
            variant_selection = {
                first_union: 'probe_opaque',
                second_union: 'dpdcid'
            }
            diagrams.append(generate_single_mermaid_diagram(
                struct, all_structs, struct_sizes, variant_selection,
                "uet_pds_ctrl ctrl_type probe"
            ))

            # Variant 2: Other CTRL_TYPE with SYN=0 (rsvd + dpdcid)
            variant_selection = {
                first_union: 'rsvd',
                second_union: 'dpdcid'
            }
            diagrams.append(generate_single_mermaid_diagram(
                struct, all_structs, struct_sizes, variant_selection,
                "uet_pds_ctrl other ctrl_type SYN=0"
            ))

            # Variant 3: Other CTRL_TYPE with SYN=1 (rsvd + pdc_info_psn_offset)
            variant_selection = {
                first_union: 'rsvd',
                second_union: 'pdc_info_psn_offset'
            }
            diagrams.append(generate_single_mermaid_diagram(
                struct, all_structs, struct_sizes, variant_selection,
                "uet_pds_ctrl other ctrl_type SYN=1"
            ))

        return diagrams

    # Special handling for uet_ses_req_smsg - merge unions into single diagram and use req_len
    if struct.name == 'uet_ses_req_smsg':
        # Generate a single diagram showing both unions as merged labels
        # Also use req_len instead of msg_id from uet_ses_req_cmn
        return [generate_single_mermaid_diagram(struct, all_structs, struct_sizes, {})]

    # Special handling for uet_ses_rsp_d - show rd_msg_id and payload_len as separate fields
    if struct.name == 'uet_ses_rsp_d':
        # Generate a single diagram with the union fields expanded
        return [generate_single_mermaid_diagram(struct, all_structs, struct_sizes, {})]

    # Special handling for uet_ses_req_onm - use rsvd_req_len instead of msg_id and rename hd to rsv
    if struct.name == 'uet_ses_req_onm':
        # Generate a single diagram with rsvd_req_len variant and hd flag renamed to rsv
        return [generate_single_mermaid_diagram(struct, all_structs, struct_sizes, {})]

    # Special handling for uet_ses_req_std - generate 4 specific configurations
    if struct.name == 'uet_ses_req_std':
        diagrams = []

        # Case 1: SOM=1 - buf_off, "[ mem_key | match_bits ]", cmpl_data
        diagrams.append(generate_single_mermaid_diagram(
            struct, all_structs, struct_sizes,
            {'uet_ses_req_std_case': 'som1'},
            "uet_ses_req_std SOM=1"
        ))

        # Case 2: SOM=0 - buf_off, "[ mem_key | match_bits ]", payload_len, msg_off
        diagrams.append(generate_single_mermaid_diagram(
            struct, all_structs, struct_sizes,
            {'uet_ses_req_std_case': 'som0'},
            "uet_ses_req_std SOM=0"
        ))

        # Case 3: deferrable send (ds) - src_restart_token, dst_restart_token, match_bits, cmpl_data
        diagrams.append(generate_single_mermaid_diagram(
            struct, all_structs, struct_sizes,
            {'uet_ses_req_std_case': 'ds'},
            "uet_ses_req_std deferrable send"
        ))

        # Case 4: deferrable send ready to restart (ds_rtr) - buf_off, ini_restart_token_rtr, tgt_restart_token_rtr, cmpl_data
        diagrams.append(generate_single_mermaid_diagram(
            struct, all_structs, struct_sizes,
            {'uet_ses_req_std_case': 'ds_rtr'},
            "uet_ses_req_std deferrable send ready to restart"
        ))

        return diagrams

    # First, identify all union fields
    union_fields = []
    for field in struct.fields:
        if '[' in field.name and '|' in field.name:
            # Parse union alternatives
            union_match = re.search(r'\[([^\]]+)\]', field.name)
            if union_match:
                alternatives = [alt.strip() for alt in union_match.group(1).split('|')]
                union_fields.append({
                    'field': field,
                    'alternatives': alternatives
                })

    # If no unions, generate single diagram
    if not union_fields:
        return [generate_single_mermaid_diagram(struct, all_structs, struct_sizes, {})]

    # Generate one diagram per union variant
    diagrams = []
    for union_info in union_fields:
        for alt_name in union_info['alternatives']:
            # Create a variant selection dict
            variant_selection = {union_info['field'].name: alt_name}
            variant_title = f"{struct.name} variant {alt_name}"
            diagrams.append(generate_single_mermaid_diagram(
                struct, all_structs, struct_sizes, variant_selection, variant_title
            ))

    return diagrams

def generate_single_mermaid_diagram(struct: Struct, all_structs: dict, struct_sizes: dict,
                                   variant_selection: dict = {}, custom_title: str = None) -> str:
    """Generate a single mermaid packet diagram for a structure (possibly a variant)"""
    lines = []
    lines.append("```mermaid")
    lines.append("---")
    title = custom_title if custom_title else struct.name
    lines.append(f"title: {title}")
    lines.append("---")
    lines.append("packet-beta")

    current_bit = 0
    used_bitfields = set()  # Track which bit fields have been used

    for field in struct.fields:
        field_start_bit = current_bit
        field_size = 0

        # Special handling for uet_ses_rsp_d - insert rd_msg_id before payload_len
        if struct.name == 'uet_ses_rsp_d' and field.name == 'payload_len':
            # This field is from the union - insert rd_msg_id first, then payload_len
            # rd_msg_id: 16 bits (current_bit to current_bit+15)
            lines.append(f"{current_bit}-{current_bit + 15}: \"rd_msg_id\"")
            # payload_len: 16 bits (current_bit+16 to current_bit+31)
            lines.append(f"{current_bit + 16}-{current_bit + 31}: \"payload_len\"")
            current_bit += 32
            continue

        # Special handling for uet_ses_req_std cases
        if struct.name == 'uet_ses_req_std' and 'uet_ses_req_std_case' in variant_selection:
            case = variant_selection['uet_ses_req_std_case']

            # Handle union 1: buf_off | restart_token
            if '[' in field.name and 'buf_off' in field.name:
                if case in ['som1', 'som0', 'ds_rtr']:
                    # Use buf_off
                    lines.append(f"{current_bit}-{current_bit + 63}: \"buf_off\"")
                    current_bit += 64
                    continue
                elif case == 'ds':
                    # Break down restart_token into src_restart_token (32 bits) and dst_restart_token (32 bits)
                    lines.append(f"{current_bit}-{current_bit + 31}: \"src_restart_token\"")
                    lines.append(f"{current_bit + 32}-{current_bit + 63}: \"dst_restart_token\"")
                    current_bit += 64
                    continue

            # Skip initiator field processing, let it fall through

            # Handle union 2: mem_key | match_bits | restart_token_rtr
            if '[' in field.name and 'mem_key' in field.name:
                if case in ['som1', 'som0']:
                    # Show as merged: "[ mem_key | match_bits ]"
                    lines.append(f"{current_bit}-{current_bit + 63}: \"[mem_key | match_bits]\"")
                    current_bit += 64
                    continue
                elif case == 'ds':
                    # Use match_bits
                    lines.append(f"{current_bit}-{current_bit + 63}: \"match_bits\"")
                    current_bit += 64
                    continue
                elif case == 'ds_rtr':
                    # Break down restart_token_rtr into ini_restart_token_rtr (32 bits) and tgt_restart_token_rtr (32 bits)
                    lines.append(f"{current_bit}-{current_bit + 31}: \"ini_restart_token_rtr\"")
                    lines.append(f"{current_bit + 32}-{current_bit + 63}: \"tgt_restart_token_rtr\"")
                    current_bit += 64
                    continue

            # Handle union 3: cmpl_data | payload_len_msg_off
            if '[' in field.name and 'cmpl_data' in field.name:
                if case in ['som1', 'ds', 'ds_rtr']:
                    # Use cmpl_data (renamed to hdr_data for output)
                    lines.append(f"{current_bit}-{current_bit + 63}: \"hdr_data\"")
                    current_bit += 64
                    continue
                elif case == 'som0':
                    # Break down payload_len_msg_off into payload_len and msg_off
                    # Field is 64 bits, in big-endian packet order:
                    # reserved (18 bits): current_bit + 0 to current_bit + 17
                    # payload_len (14 bits): current_bit + 18 to current_bit + 31
                    # msg_off (32 bits): current_bit + 32 to current_bit + 63
                    lines.append(f"{current_bit}-{current_bit + 17}: \"rsv\"")
                    lines.append(f"{current_bit + 18}-{current_bit + 31}: \"payload_len\"")
                    lines.append(f"{current_bit + 32}-{current_bit + 63}: \"msg_off\"")
                    current_bit += 64
                    continue

        # Check if this is a union field and we have a variant selection
        selected_field_name = field.name
        if field.name in variant_selection:
            selected_field_name = variant_selection[field.name]

        # Determine field size
        if field.type in struct_sizes:
            field_size = struct_sizes[field.type]
        elif field.type in TYPE_SIZES or field.bit_width > 0:
            field_size = field.bit_width
        else:
            field_size = 32  # Unknown size placeholder

        # Check if this is a nested struct that should be expanded inline
        if field.type in all_structs and selected_field_name in struct.nested_flags:
            # Expand the nested struct inline, applying flag definitions
            nested_struct = all_structs[field.type]
            custom_flag_defs = struct.nested_flags[selected_field_name]

            # The nested struct is typically a union with bit fields (e.g., type_next_flags)
            # We need to render the bit fields, but replace the "flags" portion with custom_flag_defs
            # Get the nested struct's field (should be the union field)
            for nested_field in nested_struct.fields:
                nested_selected = nested_field.name

                # If this is a union field, pick the appropriate alternative
                # For ctrl structures, use type_ctrl_flags; otherwise use type_next_flags
                if '[' in nested_selected and '|' in nested_selected:
                    union_match = re.search(r'\[([^\]]+)\]', nested_selected)
                    if union_match:
                        alternatives = [alt.strip() for alt in union_match.group(1).split('|')]
                        # Pick variant based on parent structure name
                        if 'ctrl' in struct.name.lower():
                            # For ctrl structures, prefer type_ctrl_flags
                            nested_selected = next((alt for alt in alternatives if 'ctrl' in alt.lower()), alternatives[0])
                        else:
                            # For other structures, prefer type_next_flags
                            nested_selected = next((alt for alt in alternatives if 'next' in alt.lower()), alternatives[0])

                # Check if there's a variant selection for this nested field
                if nested_field.name in variant_selection:
                    nested_selected = variant_selection[nested_field.name]

                # Get bit fields for this nested field
                nested_bitfields = []
                if nested_selected in nested_struct.bit_fields:
                    nested_bitfields = nested_struct.bit_fields[nested_selected]
                elif nested_selected in FIELD_BITFIELD_CACHE:
                    nested_bitfields = FIELD_BITFIELD_CACHE[nested_selected]

                if nested_bitfields:
                    # We have bit fields - render them, but replace "flags" with custom definitions
                    nested_field_size = TYPE_SIZES.get(nested_field.type, 16)

                    # Build a list of bit fields, replacing "flags" with custom ones
                    # Also filter out variant-specific fields that don't match
                    final_bitfields = []
                    for bf in nested_bitfields:
                        if 'flags' in bf.name.lower():
                            # Replace this with custom flag definitions
                            # The custom flags are relative to the flags field (bits 0-6)
                            # The flags field itself is at bf.start_bit to bf.end_bit
                            flags_start = bf.start_bit
                            flags_size = bf.end_bit - bf.start_bit + 1

                            if custom_flag_defs:
                                # We have custom flag definitions - use them
                                for custom_bf in custom_flag_defs:
                                    # Adjust custom flag positions to be relative to the full 16-bit field
                                    adjusted_bf = BitField(
                                        name=custom_bf.name,
                                        start_bit=flags_start + custom_bf.start_bit,
                                        end_bit=flags_start + custom_bf.end_bit,
                                        mask=custom_bf.mask,
                                        shift=custom_bf.shift
                                    )
                                    final_bitfields.append(adjusted_bf)
                            else:
                                # No custom flags defined - rename "flags" to "rsv"
                                rsv_bf = BitField(
                                    name='rsv',
                                    start_bit=bf.start_bit,
                                    end_bit=bf.end_bit,
                                    mask=bf.mask,
                                    shift=bf.shift
                                )
                                final_bitfields.append(rsv_bf)
                        else:
                            # Keep the original bit field (type, next_hdr, etc.)
                            # But filter based on variant selection
                            # If selected variant is type_next_flags, include next_hdr, not ctrl_type
                            if 'next' in nested_selected.lower() and 'ctrl' in bf.name.lower():
                                continue  # Skip ctrl_type when showing type_next_flags
                            elif 'ctrl' in nested_selected.lower() and 'next' in bf.name.lower():
                                continue  # Skip next_hdr when showing type_ctrl_flags
                            final_bitfields.append(bf)

                    # Now render the final bit fields
                    final_bitfields.sort(key=lambda bf: bf.start_bit)
                    entries = []
                    expected_bit = 0

                    for bf in final_bitfields:
                        # Check for gaps
                        if bf.start_bit > expected_bit:
                            gap_start_be = current_bit + (nested_field_size - bf.start_bit)
                            gap_end_be = current_bit + (nested_field_size - expected_bit - 1)
                            if gap_start_be == gap_end_be:
                                entries.append((gap_start_be, gap_start_be, "rsv"))
                            else:
                                entries.append((gap_start_be, gap_end_be, "rsv"))

                        # Add the bit field (big-endian)
                        abs_start = current_bit + (nested_field_size - bf.end_bit - 1)
                        abs_end = current_bit + (nested_field_size - bf.start_bit - 1)
                        entries.append((abs_start, abs_end, bf.name))
                        expected_bit = bf.end_bit + 1

                    # Check for gap at the end
                    if expected_bit < nested_field_size:
                        gap_start_be = current_bit
                        gap_end_be = current_bit + (nested_field_size - expected_bit - 1)
                        if gap_start_be == gap_end_be:
                            entries.append((gap_start_be, gap_start_be, "rsv"))
                        else:
                            entries.append((gap_start_be, gap_end_be, "rsv"))

                    # Output entries
                    entries.sort(key=lambda e: e[0])
                    for start, end, name in entries:
                        if start == end:
                            lines.append(f"{start}: \"{name}\"")
                        else:
                            lines.append(f"{start}-{end}: \"{name}\"")

                    current_bit += nested_field_size

            # Skip the normal field processing
            continue

        # Check if this field has bit-field definitions
        # Use the selected field name for variant lookups
        has_bitfields = False
        field_bitfields = []

        if selected_field_name in struct.bit_fields:
            field_bitfields = struct.bit_fields[selected_field_name]
            has_bitfields = True
        elif selected_field_name in FIELD_BITFIELD_CACHE:
            field_bitfields = FIELD_BITFIELD_CACHE[selected_field_name]
            has_bitfields = True
        # If this is a union field and the selected variant doesn't have bit fields,
        # don't fall back to other union members - just show the field as-is

        if field_bitfields:
                has_bitfields = True
                # Sort by start bit (we'll reverse positions for big-endian output)
                field_bitfields.sort(key=lambda bf: bf.start_bit)

                # Generate entries for each bit field, filling in holes with "rsv"
                # Network packets are BIG-ENDIAN: MSB comes first on the wire
                # Build a list of all entries with their packet positions

                # Filter bit fields based on variant selection
                # If we're showing a specific variant, only show relevant bit fields
                filtered_bitfields = []
                if selected_field_name != field.name and '[' in field.name:
                    # This is a union variant - filter bit fields
                    # Special handling for next_hdr vs ctrl_type variants
                    for bf in field_bitfields:
                        # Check if bit field name is related to the selected variant
                        # For next_hdr/ctrl_type variants, filter appropriately
                        if 'next_hdr' in bf.name.lower() or 'ctrl_type' in bf.name.lower():
                            # This is a variant-specific bit field
                            if 'next' in selected_field_name.lower() and 'next' in bf.name.lower():
                                filtered_bitfields.append(bf)
                            elif 'ctrl' in selected_field_name.lower() and 'ctrl' in bf.name.lower():
                                filtered_bitfields.append(bf)
                        else:
                            # Not variant-specific, include it
                            filtered_bitfields.append(bf)
                else:
                    # Not a union, include all bit fields
                    filtered_bitfields = field_bitfields

                entries = []

                expected_bit = 0  # Track expected next bit position (relative to field, little-endian)
                for bf in filtered_bitfields:
                    # Check if there's a gap before this bit field
                    if bf.start_bit > expected_bit:
                        # Fill the gap with reserved bits
                        # Convert to big-endian packet positions
                        gap_width = bf.start_bit - expected_bit
                        # In big-endian, the gap maps to the corresponding reversed position
                        gap_start_be = field_start_bit + (field_size - bf.start_bit)
                        gap_end_be = field_start_bit + (field_size - expected_bit - 1)

                        if gap_start_be == gap_end_be:
                            entries.append((gap_start_be, gap_start_be, "rsv"))
                        else:
                            entries.append((gap_start_be, gap_end_be, "rsv"))

                    # Convert bit positions from little-endian (SHIFT-based) to big-endian (packet order)
                    # For big-endian: MSB comes first, so we reverse within the field
                    abs_start = field_start_bit + (field_size - bf.end_bit - 1)
                    abs_end = field_start_bit + (field_size - bf.start_bit - 1)

                    entries.append((abs_start, abs_end, bf.name))

                    # Mark this bit field as used
                    used_bitfields.add(id(bf))

                    # Update expected next bit
                    expected_bit = bf.end_bit + 1

                # Check if there's a gap at the end of the field
                if expected_bit < field_size:
                    # Convert to big-endian packet positions
                    gap_start_be = field_start_bit
                    gap_end_be = field_start_bit + (field_size - expected_bit - 1)

                    if gap_start_be == gap_end_be:
                        entries.append((gap_start_be, gap_start_be, "rsv"))
                    else:
                        entries.append((gap_start_be, gap_end_be, "rsv"))

                # Sort entries by start bit (big-endian packet order)
                entries.sort(key=lambda e: e[0])

                # Output the entries
                for start, end, name in entries:
                    if start == end:
                        lines.append(f"{start}: \"{name}\"")
                    else:
                        lines.append(f"{start}-{end}: \"{name}\"")

        # If no bit fields, generate normal field entry
        if not has_bitfields:
            end_bit = current_bit + field_size - 1

            # Use selected field name for display
            display_name = selected_field_name.lower()

            if field.type in struct_sizes and field.type in all_structs:
                # Nested struct - expand it inline recursively
                nested_struct = all_structs[field.type]
                nested_lines = expand_nested_struct_fields(nested_struct, all_structs, struct_sizes,
                                                           current_bit, variant_selection, struct.name)
                lines.extend(nested_lines)
            elif field.is_array:
                if current_bit == end_bit:
                    lines.append(f"{current_bit}: \"{display_name}[{field.array_size}]\"")
                else:
                    lines.append(f"{current_bit}-{end_bit}: \"{display_name}[{field.array_size}]\"")
            else:
                if current_bit == end_bit:
                    lines.append(f"{current_bit}: \"{display_name}\"")
                else:
                    lines.append(f"{current_bit}-{end_bit}: \"{display_name}\"")

        current_bit += field_size

    lines.append("```")
    lines.append("")

    return '\n'.join(lines)

def expand_nested_struct_fields(struct: Struct, all_structs: dict, struct_sizes: dict,
                                 current_bit: int, variant_selection: dict, parent_struct_name: str = None) -> List[str]:
    """
    Recursively expand all fields of a nested struct, returning a list of line entries.
    This handles nested structs by expanding them inline.

    Args:
        parent_struct_name: Name of the parent structure containing this nested struct

    Returns:
        List of strings representing the mermaid diagram lines for this struct's fields
    """
    lines = []
    bit_offset = current_bit

    # Special handling for uet_ses_req_cmn when nested in uet_ses_req_onm or uet_ses_req_smsg
    is_onm_context = (parent_struct_name in ['uet_ses_req_onm', 'uet_ses_req_smsg'] and struct.name == 'uet_ses_req_cmn')

    # Special handling for uet_pds_prlg when nested in uet_pds_uud_req (rename flags to rsv)
    is_uud_context = (parent_struct_name == 'uet_pds_uud_req' and struct.name == 'uet_pds_prlg')

    for field in struct.fields:
        field_start_bit = bit_offset
        field_size = 0

        # Check if this is a union field and we have a variant selection
        selected_field_name = field.name
        if field.name in variant_selection:
            selected_field_name = variant_selection[field.name]

        # For uet_ses_req_onm and uet_ses_req_smsg context, select rsvd_req_len instead of msg_id
        if is_onm_context and '[' in field.name and 'msg_id' in field.name:
            # This is the union - select rsvd_req_len
            selected_field_name = 'rsvd_req_len'
        elif '[' in field.name and '|' in field.name:
            # This is a union field without a variant selection - pick the first alternative
            union_match = re.search(r'\[([^\]]+)\]', field.name)
            if union_match:
                alternatives = [alt.strip() for alt in union_match.group(1).split('|')]
                selected_field_name = alternatives[0] if alternatives else field.name

        # Determine field size
        if field.type in struct_sizes:
            field_size = struct_sizes[field.type]
        elif field.type in TYPE_SIZES or field.bit_width > 0:
            field_size = field.bit_width
        else:
            field_size = 32  # Unknown size placeholder

        # Check if this is a nested struct - expand it recursively
        if field.type in all_structs:
            nested_struct = all_structs[field.type]

            # Check if this nested struct has custom flag definitions from the parent
            if selected_field_name in struct.nested_flags:
                # Handle custom flag expansion for nested struct (like uet_pds_prlg)
                custom_flag_defs = struct.nested_flags[selected_field_name]

                # The nested struct (e.g., uet_pds_prlg) needs special handling
                # It has a union field that contains bit fields, and we need to replace
                # the "flags" portion with custom flags
                for nested_field in nested_struct.fields:
                    nested_field_size = 0
                    nested_selected = nested_field.name

                    # Handle union fields
                    if '[' in nested_selected and '|' in nested_selected:
                        union_match = re.search(r'\[([^\]]+)\]', nested_selected)
                        if union_match:
                            alternatives = [alt.strip() for alt in union_match.group(1).split('|')]
                            # Pick variant based on parent structure name
                            if 'ctrl' in struct.name.lower():
                                nested_selected = next((alt for alt in alternatives if 'ctrl' in alt.lower()), alternatives[0])
                            else:
                                nested_selected = next((alt for alt in alternatives if 'next' in alt.lower()), alternatives[0])

                    # Get field size
                    if nested_field.type in struct_sizes:
                        nested_field_size = struct_sizes[nested_field.type]
                    elif nested_field.type in TYPE_SIZES:
                        nested_field_size = TYPE_SIZES[nested_field.type]
                    else:
                        nested_field_size = nested_field.bit_width

                    # Get bit fields for this nested field
                    nested_bitfields = []
                    if nested_selected in nested_struct.bit_fields:
                        nested_bitfields = nested_struct.bit_fields[nested_selected]
                    elif nested_selected in FIELD_BITFIELD_CACHE:
                        nested_bitfields = FIELD_BITFIELD_CACHE[nested_selected]

                    if nested_bitfields:
                        # Build bit fields, replacing "flags" with custom ones
                        final_bitfields = []
                        for bf in nested_bitfields:
                            if 'flags' in bf.name.lower():
                                # Replace with custom flag definitions
                                flags_start = bf.start_bit
                                for custom_bf in custom_flag_defs:
                                    adjusted_bf = BitField(
                                        name=custom_bf.name,
                                        start_bit=flags_start + custom_bf.start_bit,
                                        end_bit=flags_start + custom_bf.end_bit,
                                        mask=custom_bf.mask,
                                        shift=custom_bf.shift
                                    )
                                    final_bitfields.append(adjusted_bf)
                            else:
                                # Filter based on variant
                                if 'next' in nested_selected.lower() and 'ctrl' in bf.name.lower():
                                    continue
                                elif 'ctrl' in nested_selected.lower() and 'next' in bf.name.lower():
                                    continue
                                final_bitfields.append(bf)

                        # Render the bit fields
                        final_bitfields.sort(key=lambda bf: bf.start_bit)
                        entries = []
                        expected_bit = 0

                        for bf in final_bitfields:
                            if bf.start_bit > expected_bit:
                                gap_start_be = bit_offset + (nested_field_size - bf.start_bit)
                                gap_end_be = bit_offset + (nested_field_size - expected_bit - 1)
                                if gap_start_be == gap_end_be:
                                    entries.append((gap_start_be, gap_start_be, "rsv"))
                                else:
                                    entries.append((gap_start_be, gap_end_be, "rsv"))

                            abs_start = bit_offset + (nested_field_size - bf.end_bit - 1)
                            abs_end = bit_offset + (nested_field_size - bf.start_bit - 1)
                            entries.append((abs_start, abs_end, bf.name))
                            expected_bit = bf.end_bit + 1

                        if expected_bit < nested_field_size:
                            gap_start_be = bit_offset
                            gap_end_be = bit_offset + (nested_field_size - expected_bit - 1)
                            if gap_start_be == gap_end_be:
                                entries.append((gap_start_be, gap_start_be, "rsv"))
                            else:
                                entries.append((gap_start_be, gap_end_be, "rsv"))

                        entries.sort(key=lambda e: e[0])
                        for start, end, name in entries:
                            if start == end:
                                lines.append(f"{start}: \"{name}\"")
                            else:
                                lines.append(f"{start}-{end}: \"{name}\"")

                    bit_offset += nested_field_size
                # Don't increment bit_offset at the end - we already did it above
                continue  # Skip to next field

            else:
                # Regular nested struct - expand recursively
                nested_lines = expand_nested_struct_fields(nested_struct, all_structs, struct_sizes,
                                                           bit_offset, variant_selection, struct.name)
                lines.extend(nested_lines)
                # bit_offset will be incremented by field_size at the end of the loop

        else:
            # Regular field - check for bit fields
            has_bitfields = False
            field_bitfields = []

            if selected_field_name in struct.bit_fields:
                field_bitfields = struct.bit_fields[selected_field_name]
                has_bitfields = True
            elif selected_field_name in FIELD_BITFIELD_CACHE:
                field_bitfields = FIELD_BITFIELD_CACHE[selected_field_name]
                has_bitfields = True

            if field_bitfields:
                # Has bit fields - expand them
                field_bitfields.sort(key=lambda bf: bf.start_bit)
                entries = []
                expected_bit = 0

                # Filter bit fields based on variant selection (for union fields in nested structs)
                filtered_bitfields = []
                if '[' in field.name:
                    # This is a union variant - filter bit fields
                    for bf in field_bitfields:
                        if 'next' in selected_field_name.lower() and 'ctrl' in bf.name.lower():
                            continue
                        elif 'ctrl' in selected_field_name.lower() and 'next' in bf.name.lower():
                            continue
                        filtered_bitfields.append(bf)
                else:
                    filtered_bitfields = field_bitfields

                for bf in filtered_bitfields:
                    # Check for gaps
                    if bf.start_bit > expected_bit:
                        gap_start_be = field_start_bit + (field_size - bf.start_bit)
                        gap_end_be = field_start_bit + (field_size - expected_bit - 1)
                        if gap_start_be == gap_end_be:
                            entries.append((gap_start_be, gap_start_be, "rsv"))
                        else:
                            entries.append((gap_start_be, gap_end_be, "rsv"))

                    # Add bit field (big-endian)
                    abs_start = field_start_bit + (field_size - bf.end_bit - 1)
                    abs_end = field_start_bit + (field_size - bf.start_bit - 1)

                    # Special handling for uet_ses_req_onm and uet_ses_req_smsg
                    field_name = bf.name
                    if is_onm_context:
                        # Rename 'len' to 'req_len' for both uet_ses_req_onm and uet_ses_req_smsg
                        if field_name == 'len':
                            field_name = 'req_len'
                        # Only rename 'hd' to 'rsv' for uet_ses_req_onm (not for uet_ses_req_smsg)
                        elif field_name == 'hd' and parent_struct_name == 'uet_ses_req_onm':
                            field_name = 'rsv'

                    # Special handling for uet_pds_uud_req - rename 'flags' to 'rsv'
                    if is_uud_context and field_name == 'flags':
                        field_name = 'rsv'

                    entries.append((abs_start, abs_end, field_name))
                    expected_bit = bf.end_bit + 1

                # Check for gap at the end
                if expected_bit < field_size:
                    gap_start_be = field_start_bit
                    gap_end_be = field_start_bit + (field_size - expected_bit - 1)
                    if gap_start_be == gap_end_be:
                        entries.append((gap_start_be, gap_start_be, "rsv"))
                    else:
                        entries.append((gap_start_be, gap_end_be, "rsv"))

                # Output entries
                entries.sort(key=lambda e: e[0])
                for start, end, name in entries:
                    if start == end:
                        lines.append(f"{start}: \"{name}\"")
                    else:
                        lines.append(f"{start}-{end}: \"{name}\"")
            else:
                # No bit fields - show as simple field
                end_bit = bit_offset + field_size - 1
                display_name = selected_field_name.lower()

                if field.is_array:
                    if bit_offset == end_bit:
                        lines.append(f"{bit_offset}: \"{display_name}[{field.array_size}]\"")
                    else:
                        lines.append(f"{bit_offset}-{end_bit}: \"{display_name}[{field.array_size}]\"")
                else:
                    if bit_offset == end_bit:
                        lines.append(f"{bit_offset}: \"{display_name}\"")
                    else:
                        lines.append(f"{bit_offset}-{end_bit}: \"{display_name}\"")

        bit_offset += field_size

    return lines

def generate_image_file(mermaid_code: str, output_path: str, format: str = 'png') -> bool:
    """
    Generate an image file from mermaid code using mmdc command line tool.

    Args:
        mermaid_code: The mermaid diagram code (without markdown fences)
        output_path: Path to save the output image
        format: Output format (png, svg, pdf)

    Returns:
        True if successful, False otherwise
    """
    # Create a temporary file for the mermaid code
    with tempfile.NamedTemporaryFile(mode='w', suffix='.mmd', delete=False) as f:
        temp_mmd = f.name
        f.write(mermaid_code)

    try:
        # Call mmdc to generate the image
        # The format is determined by the output file extension
        cmd = ['mmdc', '-s', '2', '-i', temp_mmd, '-o', output_path]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"Error generating {output_path}: {result.stderr}", file=sys.stderr)
            return False

        print(f"Generated: {output_path}")
        return True

    except FileNotFoundError:
        print("Error: mmdc command not found. Please install mermaid-cli:", file=sys.stderr)
        print("  npm install -g @mermaid-js/mermaid-cli", file=sys.stderr)
        return False
    finally:
        # Clean up temp file
        if os.path.exists(temp_mmd):
            os.unlink(temp_mmd)

def extract_mermaid_from_markdown(markdown_diagram: str) -> str:
    """Extract just the mermaid code from a markdown code block"""
    # Remove the opening ```mermaid and closing ```
    lines = markdown_diagram.strip().split('\n')
    if lines[0].startswith('```'):
        lines = lines[1:]  # Remove first line (```mermaid)
    if lines and lines[-1].startswith('```'):
        lines = lines[:-1]  # Remove last line (```)
    return '\n'.join(lines)

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Generate Mermaid packet diagrams from C structure definitions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate markdown to stdout (default)
  %(prog)s > packet_diagrams.md

  # Generate PNG image files
  %(prog)s --generate-images

  # Generate SVG image files
  %(prog)s --generate-images --format svg

  # Generate images to a specific directory
  %(prog)s --generate-images --output-dir diagrams/
        """
    )
    parser.add_argument(
        '-i', '--generate-images',
        action='store_true',
        help='Generate image files using mmdc instead of markdown output'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['png', 'svg', 'pdf'],
        default='png',
        help='Output image format (default: png)'
    )
    parser.add_argument(
        '-o', '--output-dir',
        default='.',
        help='Output directory for image files (default: current directory)'
    )
    parser.add_argument(
        '--input',
        default='../uet_pkt_hdr.h',
        help='Input header file (default: ../uet_pkt_hdr.h)'
    )

    args = parser.parse_args()

    # Clear global cache
    global FIELD_BITFIELD_CACHE
    FIELD_BITFIELD_CACHE = {}

    # Read the header file
    header_file = args.input

    try:
        with open(header_file, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: Could not find {header_file}", file=sys.stderr)
        sys.exit(1)

    # Extract structures
    structs = extract_structs(content)

    # Calculate struct sizes
    struct_sizes = calculate_struct_sizes(structs)

    # If generating images, create output directory
    if args.generate_images:
        os.makedirs(args.output_dir, exist_ok=True)
        success_count = 0
        error_count = 0

    # Generate output
    if not args.generate_images:
        # Default: output markdown to stdout
        print(f"# UET Packet Header Diagrams\n")
        print(f"Generated from `{header_file}`\n")
        print("---\n")

    # Generate diagrams for each structure
    for struct_name, struct in structs.items():
        # Generate all variants (if unions exist, this returns multiple diagrams)
        diagrams = generate_mermaid_diagrams(struct, structs, struct_sizes)

        for i, diagram in enumerate(diagrams):
            if args.generate_images:
                # Generate image file
                # Extract the title from the diagram to create a meaningful filename
                title_match = re.search(r'title:\s*(.+)', diagram)
                if title_match:
                    title = title_match.group(1).strip()
                    # Convert title to filename-safe format
                    filename = title.replace(' ', '_').replace(':', '-')
                    filename = re.sub(r'[^\w\-]', '', filename)
                else:
                    # Fallback filename
                    if i == 0:
                        filename = struct_name
                    else:
                        filename = f"{struct_name}_variant_{i+1}"

                output_path = os.path.join(args.output_dir, f"{filename}.{args.format}")

                # Extract mermaid code from markdown
                mermaid_code = extract_mermaid_from_markdown(diagram)

                # Generate the image
                if generate_image_file(mermaid_code, output_path, args.format):
                    success_count += 1
                else:
                    error_count += 1

            else:
                # Output markdown to stdout
                # For the first diagram (or if there's only one), use the regular header
                if i == 0:
                    print(f"## {struct.name}\n")
                    if struct.is_packed:
                        print("*(packed structure)*\n")
                    if struct_name in struct_sizes:
                        print(f"**Size:** {struct_sizes[struct_name]} bits ({struct_sizes[struct_name] // 8} bytes)\n")
                else:
                    # For additional variants, use a sub-header
                    print(f"### {struct.name} - variant {i+1}\n")

                print(diagram)
                print("---\n")

    # Print summary for image generation
    if args.generate_images:
        print(f"\nGeneration complete: {success_count} succeeded, {error_count} failed", file=sys.stderr)

if __name__ == "__main__":
    main()
