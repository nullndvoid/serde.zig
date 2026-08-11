const std = @import("std");
const builtin = @import("builtin");

comptime {
    const v = builtin.zig_version;
    if (!(v.major == 0 and v.minor >= 16)) {
        @compileError("src/compat_0_16.zig requires Zig 0.16+");
    }
}

pub const Io = std.Io;
pub const File = Io.File;
pub const Reader = Io.Reader;
pub const Writer = Io.Writer;
pub const Limit = Io.Limit;
pub const AllocatingWriter = Writer.Allocating;
pub const ArrayList = std.ArrayList;
pub const ArrayListUnmanaged = std.ArrayListUnmanaged;
pub const StringHashMap = std.StringHashMap;

pub fn StringArrayHashMap(comptime V: type) type {
    return std.array_hash_map.String(V);
}

pub fn staticBitSetEmpty(comptime size: usize) std.StaticBitSet(size) {
    const BitSet = std.StaticBitSet(size);
    if (@hasDecl(BitSet, "empty")) return BitSet.empty;
    return BitSet.initEmpty();
}

pub fn intToEnum(comptime T: type, value: anytype) ?T {
    return std.enums.fromInt(T, value);
}

pub fn intType(comptime signedness: std.builtin.Signedness, comptime bits: u16) type {
    if (builtin.zig_version.minor == 16) return std.meta.Int(signedness, bits);
    return @Int(signedness, bits);
}

pub fn trimEnd(comptime T: type, slice: []const T, values_to_strip: []const T) []const T {
    return std.mem.trimEnd(T, slice, values_to_strip);
}

pub fn openFileForRead(path: []const u8) !File {
    return std.Io.Dir.cwd().openFile(std.Options.debug_io, path, .{});
}

pub fn closeFile(file: File) void {
    file.close(std.Options.debug_io);
}

pub fn writeFile(path: []const u8, data: []const u8) !void {
    try std.Io.Dir.cwd().writeFile(std.Options.debug_io, .{ .sub_path = path, .data = data });
}

pub fn writeStdout(data: []const u8) !void {
    try std.Io.File.stdout().writeStreamingAll(std.Options.debug_io, data);
}

pub fn deleteFile(path: []const u8) !void {
    try std.Io.Dir.cwd().deleteFile(std.Options.debug_io, path);
}

pub fn fileReaderStreaming(file: File, buffer: []u8) @TypeOf(file.readerStreaming(std.Options.debug_io, buffer)) {
    return file.readerStreaming(std.Options.debug_io, buffer);
}

pub fn readerAllocRemaining(reader: anytype, allocator: std.mem.Allocator, limit: Limit) ![]u8 {
    return reader.interface.allocRemaining(allocator, limit);
}

pub fn readFileAlloc(allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    const file = try openFileForRead(path);
    defer closeFile(file);

    var buffer: [4096]u8 = undefined;
    var reader = fileReaderStreaming(file, &buffer);
    return readerAllocRemaining(&reader, allocator, Limit.limited(max_bytes));
}

/// Version-stable zlib helpers used by ETF's COMPRESSED_EXT support.
/// Level 0 stores the input uncompressed, matching zlib semantics.
pub fn zlibCompress(allocator: std.mem.Allocator, input: []const u8, level: u4) ![]u8 {
    var aw: Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();
    try aw.ensureTotalCapacity(64);
    if (level == 0) {
        try aw.writer.writeAll(&.{ 0x78, 0x01 });
        var remaining = input;
        if (remaining.len == 0) try writeStoredBlock(&aw.writer, &.{}, true);
        while (remaining.len != 0) {
            const count = @min(remaining.len, std.math.maxInt(u16));
            try writeStoredBlock(&aw.writer, remaining[0..count], count == remaining.len);
            remaining = remaining[count..];
        }
        var footer: [4]u8 = undefined;
        std.mem.writeInt(u32, &footer, adler32(input), .big);
        try aw.writer.writeAll(&footer);
        return aw.toOwnedSlice();
    }
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    const selected: std.compress.flate.Compress.Options = switch (level) {
        0 => unreachable,
        1 => .level_1,
        2 => .level_2,
        3 => .level_3,
        4 => .level_4,
        5 => .level_5,
        6 => .level_6,
        7 => .level_7,
        8 => .level_8,
        else => .level_9,
    };
    var compressor = try std.compress.flate.Compress.init(&aw.writer, &window, .zlib, selected);
    try compressor.writer.writeAll(input);
    try compressor.finish();
    return aw.toOwnedSlice();
}

fn writeStoredBlock(writer: *Io.Writer, data: []const u8, final: bool) !void {
    try writer.writeByte(@intFromBool(final));
    var header: [4]u8 = undefined;
    const len: u16 = @intCast(data.len);
    std.mem.writeInt(u16, header[0..2], len, .little);
    std.mem.writeInt(u16, header[2..4], ~len, .little);
    try writer.writeAll(&header);
    try writer.writeAll(data);
}

pub fn zlibDecompress(allocator: std.mem.Allocator, input: []const u8, expected_len: usize) ![]u8 {
    var source: Io.Reader = .fixed(input);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompressor: std.compress.flate.Decompress = .init(&source, .zlib, &window);
    const limit = std.math.add(usize, expected_len, 1) catch return error.InvalidCompressedData;
    const output = try allocator.alloc(u8, limit);
    errdefer allocator.free(output);
    var sink: Io.Writer = .fixed(output);
    const actual = decompressor.reader.streamRemaining(&sink) catch return error.InvalidCompressedData;
    if (actual != expected_len or decompressor.err != null or source.seek != source.end) return error.InvalidCompressedData;
    const wire_adler = switch (decompressor.container_metadata) {
        .zlib => |zlib| zlib.adler,
        else => unreachable,
    };
    if (wire_adler != adler32(output[0..expected_len])) return error.InvalidCompressedData;
    return allocator.realloc(output, expected_len);
}

fn adler32(data: []const u8) u32 {
    const modulus = 65521;
    var a: u32 = 1;
    var b: u32 = 0;
    for (data) |byte| {
        a = (a + byte) % modulus;
        b = (b + a) % modulus;
    }
    return (b << 16) | a;
}
