const std = @import("std");
const builtin = @import("builtin");
const elf = std.elf;
const assert = std.debug.assert;

const R_AMD64_RELATIVE = 8;
const R_386_RELATIVE = 8;
const R_ARM_RELATIVE = 23;
const R_AARCH64_RELATIVE = 1027;
const R_RISCV_RELATIVE = 3;
const R_SPARC_RELATIVE = 22;

const R_RELATIVE = switch (builtin.cpu.arch) {
    .x86 => R_386_RELATIVE,
    .x86_64 => R_AMD64_RELATIVE,
    .arm => R_ARM_RELATIVE,
    .aarch64 => R_AARCH64_RELATIVE,
    .riscv64 => R_RISCV_RELATIVE,
    else => @compileError("Missing R_RELATIVE definition for this target"),
};

// Obtain a pointer to the _DYNAMIC array.
// We have to compute its address as a PC-relative quantity not to require a
// relocation that, at this point, is not yet applied.
fn getDynamicSymbol() [*]elf.Dyn {
    return switch (builtin.cpu.arch) {
        .x86 => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ call 1f
            \\ 1: pop %[ret]
            \\ lea _DYNAMIC-1b(%[ret]), %[ret]
            : [ret] "=r" (-> [*]elf.Dyn),
        ),
        .x86_64 => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ lea _DYNAMIC(%%rip), %[ret]
            : [ret] "=r" (-> [*]elf.Dyn),
        ),
        // Work around the limited offset range of `ldr`
        .arm => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ ldr %[ret], 1f
            \\ add %[ret], pc
            \\ b 2f
            \\ 1: .word _DYNAMIC-1b
            \\ 2:
            : [ret] "=r" (-> [*]elf.Dyn),
        ),
        // A simple `adr` is not enough as it has a limited offset range
        .aarch64 => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ adrp %[ret], _DYNAMIC
            \\ add %[ret], %[ret], #:lo12:_DYNAMIC
            : [ret] "=r" (-> [*]elf.Dyn),
        ),
        .riscv64 => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ lla %[ret], _DYNAMIC
            : [ret] "=r" (-> [*]elf.Dyn),
        ),
        else => {
            @compileError("PIE startup is not yet supported for this target!");
        },
    };
}

fn relocate_android_apr1(base_addr: usize, encoded: []const u8) !void {
    var stream = std.io.fixedBufferStream(encoded);
    var reader = stream.reader();
    var paircnt = try std.leb.readULEB128(usize, reader);
    var addr = try std.leb.readULEB128(usize, reader);

    @as(*usize, @ptrFromInt(addr)).* += base_addr;
    while (paircnt != 0) : (paircnt -= 1) {
        var rlecnt = try std.leb.readULEB128(usize, reader);
        var rledelta = try std.leb.readULEB128(usize, reader);
        while (rlecnt != 0) : (rlecnt -= 1) {
            addr += rledelta;
            @as(*usize, @ptrFromInt(addr)).* += base_addr;
        }
    }
}

fn relocate_android_apa1(base_addr: usize, encoded: []const u8) !void {
    var stream = std.io.fixedBufferStream(encoded);
    var reader = stream.reader();
    var pairs = try std.leb.readILEB128(isize, reader);
    var addr = @as(isize, 0);
    var addend = @as(isize, 0);
    while (pairs != 0) : (pairs -= 1) {
        addr += try std.leb.readILEB128(isize, reader);
        addend += try std.leb.readILEB128(isize, reader);
        @as(*usize, @ptrFromInt(@as(usize, @bitCast(addr)))).* = base_addr + @as(usize, @bitCast(addend));
    }
}

fn relocate_android_aps2(base_addr: usize, encoded: []const u8) !void {
    var stream = std.io.fixedBufferStream(encoded);
    var reader = stream.reader();
    var count = try std.leb.readILEB128(isize, reader);
    var offset = try std.leb.readILEB128(isize, reader);
    var info = @as(isize, 0);

    const GROUPED_INFO = @as(u32, 1);
    const GROUPED_DELTA = @as(u32, 2);
    const GROUPED_ADDEND = @as(u32, 4);
    const HAS_ADDEND = @as(u32, 8);
    while (count != 0) : (count -= 1) {
        var size = try std.leb.readILEB128(isize, reader);
        var flags = try std.leb.readILEB128(isize, reader);
        var delta = @as(isize, 0);
        var addend = @as(isize, 0);
        if ((flags & GROUPED_DELTA) != 0) delta = try std.leb.readILEB128(isize, reader);
        if ((flags & GROUPED_INFO) != 0) info = try std.leb.readILEB128(isize, reader);
        if ((flags & GROUPED_ADDEND) != 0 and (flags & HAS_ADDEND) != 0) addend = try std.leb.readILEB128(isize, reader);
        while (size != 0) : (size -= 1) {
            if ((flags & GROUPED_DELTA) != 0) offset += delta else offset += try std.leb.readILEB128(isize, reader);
            if ((flags & GROUPED_INFO) == 0) info = try std.leb.readILEB128(isize, reader);
            if ((flags & HAS_ADDEND) != 0 and (flags & GROUPED_ADDEND) == 0) addend += try std.leb.readILEB128(isize, reader);
            if ((info & 0xff) == R_RELATIVE) {
                @as(*usize, @ptrFromInt(base_addr + @as(usize, @bitCast(offset)))).* = @as(usize, base_addr + @as(usize, @bitCast(addend)));
            }
        }
    }
}

pub fn relocate(phdrs: []elf.Phdr) void {
    @setRuntimeSafety(false);

    const dynv = getDynamicSymbol();
    // Recover the delta applied by the loader by comparing the effective and
    // the theoretical load addresses for the `_DYNAMIC` symbol.
    const base_addr = base: {
        for (phdrs) |*phdr| {
            if (phdr.p_type != elf.PT_DYNAMIC) continue;
            break :base @intFromPtr(dynv) - phdr.p_vaddr;
        }
        // This is not supposed to happen for well-formed binaries.
        std.os.abort();
    };

    var rel_addr: usize = 0;
    var rela_addr: usize = 0;
    var relr_addr: usize = 0;
    var andrel_old_addr: usize = 0;
    var andrela_addr: usize = 0;
    var rel_size: usize = 0;
    var rela_size: usize = 0;
    var relr_size: usize = 0;
    var andrel_old_size: usize = 0;
    var andrela_size: usize = 0;
    {
        var i: usize = 0;
        while (dynv[i].d_tag != elf.DT_NULL) : (i += 1) {
            switch (dynv[i].d_tag) {
                elf.DT_REL => rel_addr = base_addr + dynv[i].d_val,
                elf.DT_RELA => rela_addr = base_addr + dynv[i].d_val,
                elf.DT_RELR, elf.DT_ANDROID_RELR => relr_addr = base_addr + dynv[i].d_val,
                elf.DT_ANDROID_REL_OFFSET => andrel_old_addr = base_addr + dynv[i].d_val,
                elf.DT_ANDROID_REL, elf.DT_ANDROID_RELA => andrela_addr = base_addr + dynv[i].d_val,
                elf.DT_RELSZ => rel_size = dynv[i].d_val,
                elf.DT_RELASZ => rela_size = dynv[i].d_val,
                elf.DT_RELRSZ, elf.DT_ANDROID_RELRSZ => relr_size = dynv[i].d_val,
                elf.DT_ANDROID_REL_SIZE => andrel_old_size = dynv[i].d_val,
                elf.DT_ANDROID_RELSZ, elf.DT_ANDROID_RELASZ => andrela_size = dynv[i].d_val,
                else => {},
            }
        }
    }

    // Apply the relocations.
    if (rel_addr != 0) {
        const rel = std.mem.bytesAsSlice(elf.Rel, @as([*]u8, @ptrFromInt(rel_addr))[0..rel_size]);
        for (rel) |r| {
            if (r.r_type() != R_RELATIVE) continue;
            @as(*usize, @ptrFromInt(base_addr + r.r_offset)).* += base_addr;
        }
    }
    if (rela_addr != 0) {
        const rela = std.mem.bytesAsSlice(elf.Rela, @as([*]u8, @ptrFromInt(rela_addr))[0..rela_size]);
        for (rela) |r| {
            if (r.r_type() != R_RELATIVE) continue;
            @as(*usize, @ptrFromInt(base_addr + r.r_offset)).* = base_addr + @as(usize, @bitCast(r.r_addend));
        }
    }
    if (relr_addr != 0) {
        const relr = std.mem.bytesAsSlice(elf.Relr, @as([*]u8, @ptrFromInt(relr_addr))[0..relr_size]);
        var offset: elf.Relr = 0;
        for (relr) |r| {
            if ((r & 1) == 1) {
                const next_offset: elf.Relr = offset + (@sizeOf(elf.Relr) * 8 - 1) * @sizeOf(elf.Relr);
                var iter: elf.Relr = r;
                while (iter != 0) {
                    iter >>= 1;
                    if ((iter & 1) != 0) @as(*usize, @ptrFromInt(base_addr + offset)).* += base_addr;
                    offset += @sizeOf(elf.Relr);
                }
                offset = next_offset;
            } else {
                offset = r;
                @as(*usize, @ptrFromInt(base_addr + offset)).* += base_addr;
                offset += @sizeOf(elf.Relr);
            }
        }
    }
    if (andrel_old_addr != 0 and andrel_old_size >= 4) {
        const ident = @as([*]u8, @ptrFromInt(andrel_old_addr));
        const encoded = @as([*]u8, @ptrFromInt(andrel_old_addr + 4))[0 .. andrel_old_size - 4];
        if (ident[2] == 'R') {
            relocate_android_apr1(base_addr, encoded) catch std.os.abort();
        } else if (ident[2] == 'A') {
            relocate_android_apa1(base_addr, encoded) catch std.os.abort();
        }
    }
    // Only APS2 format is implemented in lld right now
    if (andrela_addr != 0 and andrela_size >= 4) {
        const encoded = @as([*]u8, @ptrFromInt(andrela_addr + 4))[0 .. andrela_size - 4];
        relocate_android_aps2(base_addr, encoded) catch std.os.abort();
    }
}
