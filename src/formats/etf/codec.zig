const std = @import("std");
const compat = @import("compat");
const term_mod = @import("term.zig");

pub const Term = term_mod.Term;
pub const MapEntry = term_mod.MapEntry;

pub const version: u8 = 131;

pub const Tag = enum(u8) {
    record_ext = 67,
    new_float_ext = 70,
    bit_binary_ext = 77,
    compressed_ext = 80,
    atom_cache_ref = 82,
    new_pid_ext = 88,
    new_port_ext = 89,
    newer_reference_ext = 90,
    small_integer_ext = 97,
    integer_ext = 98,
    float_ext = 99,
    atom_ext = 100,
    reference_ext = 101,
    port_ext = 102,
    pid_ext = 103,
    small_tuple_ext = 104,
    large_tuple_ext = 105,
    nil_ext = 106,
    string_ext = 107,
    list_ext = 108,
    binary_ext = 109,
    small_big_ext = 110,
    large_big_ext = 111,
    new_fun_ext = 112,
    export_ext = 113,
    new_reference_ext = 114,
    small_atom_ext = 115,
    map_ext = 116,
    fun_ext = 117,
    atom_utf8_ext = 118,
    small_atom_utf8_ext = 119,
    v4_port_ext = 120,
    local_ext = 121,
};

pub const Compression = union(enum) {
    never,
    always,
    threshold: usize,
};

pub const EncodeOptions = struct {
    compression: Compression = .never,
    /// DEFLATE effort inside COMPRESSED_EXT: 0 stores the payload
    /// uncompressed, 1-9 trade speed for ratio as in zlib.
    zlib_level: u4 = 6,
    allow_legacy: bool = false,
    allow_local: bool = false,
    max_size: usize = 10 * 1024 * 1024,
    max_depth: usize = 256,
    max_collection_elements: usize = 1_000_000,
    max_bignum_bytes: usize = 1024 * 1024,
    /// Distribution-header atom references, indexed exactly as ATOM_CACHE_REF.
    atom_cache: ?[]const []const u8 = null,
};

pub const DecodeOptions = struct {
    /// Require the canonical typed profile and disable compatible coercions.
    strict: bool = false,
    max_input_size: usize = 10 * 1024 * 1024,
    max_uncompressed_size: usize = 10 * 1024 * 1024,
    max_depth: usize = 256,
    max_collection_elements: usize = 1_000_000,
    max_bignum_bytes: usize = 1024 * 1024,
    /// Distribution-header atom references, indexed exactly as ATOM_CACHE_REF.
    atom_cache: ?[]const []const u8 = null,
};

pub const EncodeError = error{
    OutOfMemory,
    WriteFailed,
    InvalidFloat,
    InvalidAtom,
    AtomTooLong,
    InvalidTerm,
    DuplicateMapKey,
    LegacyDisabled,
    LocalDisabled,
    SizeLimit,
    LengthOverflow,
    DepthLimit,
    CompressionFailed,
};

pub const DecodeError = error{
    OutOfMemory,
    InvalidVersion,
    UnexpectedTag,
    UnexpectedEof,
    TrailingData,
    InvalidFloat,
    InvalidAtom,
    AtomTooLong,
    InvalidIdentifier,
    InvalidBitBinary,
    InvalidRecord,
    InvalidFun,
    InvalidLocalTerm,
    MissingAtomCache,
    InvalidAtomCacheRef,
    DuplicateMapKey,
    SizeLimit,
    CollectionLimit,
    BignumLimit,
    DepthLimit,
    Overflow,
    DecompressionFailed,
};

/// Duplicate-map-key detector shared by the decoder and the encoder. Small
/// maps use direct pairwise comparison; larger maps use an open-addressing
/// hash index so hostile inputs cannot force quadratic time.
const MapKeyDedup = struct {
    hashes: []u64 = &.{},
    slots: []u32 = &.{},
    seed: u64,

    const linear_limit = 8;
    const empty_slot = std.math.maxInt(u32);

    fn init(allocator: std.mem.Allocator, count: usize, seed: u64) error{OutOfMemory}!MapKeyDedup {
        if (count <= linear_limit) return .{ .seed = seed };
        if (count > std.math.maxInt(u32)) return error.OutOfMemory;
        const hashes = try allocator.alloc(u64, count);
        errdefer allocator.free(hashes);
        const capacity = std.math.ceilPowerOfTwo(usize, count * 2) catch return error.OutOfMemory;
        const slots = try allocator.alloc(u32, capacity);
        @memset(slots, empty_slot);
        return .{ .hashes = hashes, .slots = slots, .seed = seed };
    }

    fn deinit(self: *MapKeyDedup, allocator: std.mem.Allocator) void {
        allocator.free(self.hashes);
        allocator.free(self.slots);
    }

    /// Registers the key of `entries[index]`; keys `0..index` must already be
    /// registered.
    fn add(self: *MapKeyDedup, entries: []const MapEntry, index: usize) error{DuplicateMapKey}!void {
        const key = entries[index].key;
        if (self.slots.len == 0) {
            for (entries[0..index]) |previous| {
                if (key.eql(previous.key)) return error.DuplicateMapKey;
            }
            return;
        }
        const key_hash = key.hash(self.seed);
        self.hashes[index] = key_hash;
        const mask = self.slots.len - 1;
        var slot = key_hash & mask;
        while (self.slots[slot] != empty_slot) : (slot = (slot + 1) & mask) {
            const other = self.slots[slot];
            if (self.hashes[other] == key_hash and entries[other].key.eql(key)) return error.DuplicateMapKey;
        }
        self.slots[slot] = @intCast(index);
    }
};

/// Encode a complete versioned ETF term. The returned slice is owned by caller.
pub fn encodeTerm(allocator: std.mem.Allocator, term: Term, options: EncodeOptions) EncodeError![]u8 {
    var body_writer: compat.Io.Writer.Allocating = .init(allocator);
    errdefer body_writer.deinit();
    try encodeTermBodyToWriter(allocator, &body_writer.writer, term, options);
    const body = try body_writer.toOwnedSlice();
    defer allocator.free(body);
    if (body.len > options.max_size) return error.SizeLimit;

    const should_compress = switch (options.compression) {
        .never => false,
        .always => true,
        .threshold => |threshold| body.len >= threshold,
    };

    var output: compat.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    output.writer.writeByte(version) catch return error.WriteFailed;
    if (!should_compress) {
        output.writer.writeAll(body) catch return error.WriteFailed;
    } else {
        if (body.len > std.math.maxInt(u32)) return error.LengthOverflow;
        const compressed = compat.zlibCompress(allocator, body, options.zlib_level) catch return error.CompressionFailed;
        defer allocator.free(compressed);
        output.writer.writeByte(@intFromEnum(Tag.compressed_ext)) catch return error.WriteFailed;
        writeInt(&output.writer, u32, @intCast(body.len)) catch return error.WriteFailed;
        output.writer.writeAll(compressed) catch return error.WriteFailed;
    }
    if (output.writer.end > options.max_size) return error.SizeLimit;
    return output.toOwnedSlice() catch return error.OutOfMemory;
}

pub fn encodeTermToWriter(
    allocator: std.mem.Allocator,
    writer: *compat.Io.Writer,
    term: Term,
    options: EncodeOptions,
) EncodeError!void {
    const bytes = try encodeTerm(allocator, term, options);
    defer allocator.free(bytes);
    writer.writeAll(bytes) catch return error.WriteFailed;
}

/// Encode one version-free term, as required after a distribution header.
pub fn encodeTermBodyToWriter(
    allocator: std.mem.Allocator,
    writer: *compat.Io.Writer,
    term: Term,
    options: EncodeOptions,
) EncodeError!void {
    var encoder = Encoder{ .allocator = allocator, .writer = writer, .options = options };
    try encoder.writeTerm(term, 0, true);
}

/// Decode one complete versioned ETF term. COMPRESSED_EXT is handled
/// transparently and checked against the configured uncompressed limit.
pub fn decodeTerm(allocator: std.mem.Allocator, input: []const u8, options: DecodeOptions) DecodeError!Term {
    if (input.len > options.max_input_size) return error.SizeLimit;
    if (input.len == 0 or input[0] != version) return error.InvalidVersion;
    if (input.len < 2) return error.UnexpectedEof;

    if (input[1] == @intFromEnum(Tag.compressed_ext)) {
        if (input.len < 6) return error.UnexpectedEof;
        const expected = std.mem.readInt(u32, input[2..6], .big);
        if (expected > options.max_uncompressed_size) return error.SizeLimit;
        const plain = compat.zlibDecompress(allocator, input[6..], expected) catch return error.DecompressionFailed;
        defer allocator.free(plain);
        var decoder = Decoder.initBody(allocator, plain, options);
        var result = try decoder.nextTopLevel();
        errdefer result.deinit(allocator);
        if (decoder.remaining() != 0) return error.TrailingData;
        return result;
    }

    var decoder = Decoder.initBody(allocator, input[1..], options);
    var result = try decoder.nextTopLevel();
    errdefer result.deinit(allocator);
    if (decoder.remaining() != 0) return error.TrailingData;
    return result;
}

/// Shared bounded ETF cursor. Distribution decoding uses this directly to
/// read consecutive version-free control and payload terms without an AST in
/// between.
pub const Decoder = struct {
    allocator: std.mem.Allocator,
    input: []const u8,
    pos: usize = 0,
    options: DecodeOptions,

    pub fn initBody(allocator: std.mem.Allocator, input: []const u8, options: DecodeOptions) Decoder {
        return .{ .allocator = allocator, .input = input, .options = options };
    }

    pub fn remaining(self: *const Decoder) usize {
        return self.input.len - self.pos;
    }

    pub fn next(self: *Decoder) DecodeError!Term {
        return self.readTerm(0, false);
    }

    pub fn nextTopLevel(self: *Decoder) DecodeError!Term {
        return self.readTerm(0, true);
    }

    fn readTerm(self: *Decoder, depth: usize, top_level: bool) DecodeError!Term {
        if (depth >= self.options.max_depth) return error.DepthLimit;
        const tag_byte = try self.readByte();
        const tag: Tag = compat.intToEnum(Tag, tag_byte) orelse return error.UnexpectedTag;
        return switch (tag) {
            .small_integer_ext => .{ .integer = try self.readByte() },
            .integer_ext => .{ .integer = try self.readSigned32() },
            .small_big_ext => self.readBig(try self.readByte()),
            .large_big_ext => self.readBig(try self.readU32()),
            .new_float_ext => self.readNewFloat(),
            .float_ext => self.readLegacyFloat(),
            .atom_utf8_ext => .{ .atom = try self.readUtf8Atom(try self.readU16()) },
            .small_atom_utf8_ext => .{ .atom = try self.readUtf8Atom(try self.readByte()) },
            .atom_ext => .{ .atom = try self.readLatin1Atom(try self.readU16()) },
            .small_atom_ext => .{ .atom = try self.readLatin1Atom(try self.readByte()) },
            .atom_cache_ref => .{ .atom = try self.readCachedAtom() },
            .new_pid_ext => .{ .pid = try self.readPid(depth, false) },
            .pid_ext => .{ .pid = try self.readPid(depth, true) },
            .new_port_ext => .{ .port = try self.readPort(depth, .new) },
            .port_ext => .{ .port = try self.readPort(depth, .legacy) },
            .v4_port_ext => .{ .port = try self.readPort(depth, .v4) },
            .reference_ext => .{ .reference = try self.readReference(depth, .legacy) },
            .new_reference_ext => .{ .reference = try self.readReference(depth, .new) },
            .newer_reference_ext => .{ .reference = try self.readReference(depth, .newer) },
            .small_tuple_ext => .{ .tuple = try self.readTerms(try self.readByte(), depth) },
            .large_tuple_ext => .{ .tuple = try self.readTerms(try self.readU32(), depth) },
            .map_ext => .{ .map = try self.readMap(try self.readU32(), depth) },
            .nil_ext => .nil,
            .string_ext => self.readStringList(try self.readU16()),
            .list_ext => try self.readList(try self.readU32(), depth),
            .binary_ext => .{ .binary = try self.readOwned(try self.readU32()) },
            .bit_binary_ext => try self.readBitBinary(try self.readU32()),
            .new_fun_ext => try self.readNewFun(depth),
            .fun_ext => try self.readLegacyFun(depth),
            .export_ext => try self.readExport(depth),
            .record_ext => try self.readRecord(depth),
            .local_ext => if (top_level)
                .{ .local = try self.readOwned(self.remaining()) }
            else
                error.InvalidLocalTerm,
            .compressed_ext => error.UnexpectedTag,
        };
    }

    fn readTerms(self: *Decoder, count: usize, depth: usize) DecodeError![]Term {
        try self.checkCollection(count);
        const out = self.allocator.alloc(Term, count) catch return error.OutOfMemory;
        var initialized: usize = 0;
        errdefer {
            for (out[0..initialized]) |*item| item.deinit(self.allocator);
            self.allocator.free(out);
        }
        for (out) |*item| {
            item.* = try self.readTerm(depth + 1, false);
            initialized += 1;
        }
        return out;
    }

    fn readMap(self: *Decoder, count: usize, depth: usize) DecodeError![]MapEntry {
        try self.checkCollection(count);
        const out = self.allocator.alloc(MapEntry, count) catch return error.OutOfMemory;
        var initialized: usize = 0;
        errdefer {
            for (out[0..initialized]) |*entry| {
                entry.key.deinit(self.allocator);
                entry.value.deinit(self.allocator);
            }
            self.allocator.free(out);
        }
        // The per-allocation seed keeps precomputed hash-collision floods
        // from degrading the dedup index.
        var dedup = try MapKeyDedup.init(self.allocator, count, @intFromPtr(out.ptr));
        defer dedup.deinit(self.allocator);
        for (out, 0..) |*entry, i| {
            entry.key = try self.readTerm(depth + 1, false);
            errdefer entry.key.deinit(self.allocator);
            try dedup.add(out, i);
            entry.value = try self.readTerm(depth + 1, false);
            initialized += 1;
        }
        return out;
    }

    fn readList(self: *Decoder, count: usize, depth: usize) DecodeError!Term {
        const elements = try self.readTerms(count, depth);
        errdefer deinitTerms(elements, self.allocator);
        const tail = try self.readTerm(depth + 1, false);
        if (tail == .nil) return .{ .list = .{ .elements = elements } };
        const tail_ptr = self.allocator.create(Term) catch return error.OutOfMemory;
        tail_ptr.* = tail;
        return .{ .list = .{ .elements = elements, .tail = tail_ptr } };
    }

    fn readStringList(self: *Decoder, count: usize) DecodeError!Term {
        try self.checkCollection(count);
        const raw = try self.readSlice(count);
        const elements = self.allocator.alloc(Term, count) catch return error.OutOfMemory;
        for (raw, 0..) |byte, i| elements[i] = .{ .integer = byte };
        return .{ .list = .{ .elements = elements } };
    }

    fn readBig(self: *Decoder, wire_count: usize) DecodeError!Term {
        if (wire_count > self.options.max_bignum_bytes) return error.BignumLimit;
        const negative_byte = try self.readByte();
        if (negative_byte > 1) return error.InvalidIdentifier;
        const wire = try self.readSlice(wire_count);
        var count = wire.len;
        while (count > 0 and wire[count - 1] == 0) count -= 1;
        if (count == 0) return .{ .integer = 0 };

        if (count <= 8) {
            var magnitude: u64 = 0;
            for (wire[0..count], 0..) |digit, i| magnitude |= @as(u64, digit) << @intCast(i * 8);
            if (negative_byte == 0 and magnitude <= std.math.maxInt(i64))
                return .{ .integer = @intCast(magnitude) };
            if (negative_byte == 1 and magnitude <= (@as(u64, 1) << 63)) {
                if (magnitude == (@as(u64, 1) << 63)) return .{ .integer = std.math.minInt(i64) };
                return .{ .integer = -@as(i64, @intCast(magnitude)) };
            }
        }
        return .{ .big_integer = .{
            .negative = negative_byte == 1,
            .magnitude = self.allocator.dupe(u8, wire[0..count]) catch return error.OutOfMemory,
        } };
    }

    fn readNewFloat(self: *Decoder) DecodeError!Term {
        const bits = try self.readU64();
        const value: f64 = @bitCast(bits);
        if (!std.math.isFinite(value)) return error.InvalidFloat;
        return .{ .float = value };
    }

    fn readLegacyFloat(self: *Decoder) DecodeError!Term {
        const bytes = try self.readSlice(31);
        const end = std.mem.indexOfScalar(u8, bytes, 0) orelse bytes.len;
        const value = std.fmt.parseFloat(f64, bytes[0..end]) catch return error.InvalidFloat;
        if (!std.math.isFinite(value)) return error.InvalidFloat;
        return .{ .float = value };
    }

    fn readPid(self: *Decoder, depth: usize, legacy: bool) DecodeError!term_mod.Pid {
        const node = try self.readAtom(depth);
        errdefer self.allocator.free(node);
        const id = try self.readU32();
        const serial = try self.readU32();
        const creation: u32 = if (legacy) try self.readByte() else try self.readU32();
        if (legacy and (id > 0x7fff or serial > 0x1fff or creation > 3)) return error.InvalidIdentifier;
        return .{ .node = node, .id = id, .serial = serial, .creation = creation };
    }

    const PortKind = enum { legacy, new, v4 };
    fn readPort(self: *Decoder, depth: usize, kind: PortKind) DecodeError!term_mod.Port {
        const node = try self.readAtom(depth);
        errdefer self.allocator.free(node);
        const id: u64 = if (kind == .v4) try self.readU64() else try self.readU32();
        const creation: u32 = if (kind == .legacy) try self.readByte() else try self.readU32();
        if (kind != .v4 and id > 0x0fffffff) return error.InvalidIdentifier;
        if (kind == .legacy and creation > 3) return error.InvalidIdentifier;
        return .{ .node = node, .id = id, .creation = creation };
    }

    const ReferenceKind = enum { legacy, new, newer };
    fn readReference(self: *Decoder, depth: usize, kind: ReferenceKind) DecodeError!term_mod.Reference {
        const count: usize = if (kind == .legacy) 1 else try self.readU16();
        if (count == 0 or count > 5) return error.InvalidIdentifier;
        const node = try self.readAtom(depth);
        errdefer self.allocator.free(node);
        if (kind == .legacy) {
            const ids = self.allocator.alloc(u32, 1) catch return error.OutOfMemory;
            errdefer self.allocator.free(ids);
            ids[0] = try self.readU32();
            const creation = try self.readByte();
            if (creation > 3 or ids[0] > 0x3ffff) return error.InvalidIdentifier;
            return .{ .node = node, .creation = creation, .ids = ids };
        }
        const creation: u32 = if (kind == .newer) try self.readU32() else try self.readByte();
        if (kind != .newer and creation > 3) return error.InvalidIdentifier;
        const ids = self.allocator.alloc(u32, count) catch return error.OutOfMemory;
        errdefer self.allocator.free(ids);
        for (ids) |*id| id.* = try self.readU32();
        if (kind == .new and ids[0] > 0x3ffff) return error.InvalidIdentifier;
        return .{ .node = node, .creation = creation, .ids = ids };
    }

    fn readBitBinary(self: *Decoder, count: usize) DecodeError!Term {
        const bits = try self.readByte();
        if (count == 0 or bits < 1 or bits > 8) return error.InvalidBitBinary;
        const bytes = try self.readOwned(count);
        errdefer self.allocator.free(bytes);
        if (bits < 8) {
            const unused: u3 = @intCast(8 - bits);
            const mask: u8 = (@as(u8, 1) << unused) - 1;
            if (bytes[bytes.len - 1] & mask != 0) return error.InvalidBitBinary;
        }
        return .{ .bit_binary = .{ .bytes = bytes, .bits = @intCast(bits) } };
    }

    fn readNewFun(self: *Decoder, depth: usize) DecodeError!Term {
        const size_start = self.pos;
        const size = try self.readU32();
        const expected_end = std.math.add(usize, size_start, size) catch return error.InvalidFun;
        if (size < 4 or expected_end > self.input.len) return error.InvalidFun;
        const arity = try self.readByte();
        const uniq_slice = try self.readSlice(16);
        var uniq: [16]u8 = undefined;
        @memcpy(&uniq, uniq_slice);
        const index = try self.readU32();
        const num_free = try self.readU32();
        const module = try self.readAtom(depth);
        errdefer self.allocator.free(module);
        const old_index = try self.readI32Term(depth);
        const old_uniq = try self.readI32Term(depth);
        const pid_term = try self.readTerm(depth + 1, false);
        const pid = switch (pid_term) {
            .pid => |v| v,
            else => {
                var invalid = pid_term;
                invalid.deinit(self.allocator);
                return error.InvalidFun;
            },
        };
        errdefer self.allocator.free(pid.node);
        const free_vars = try self.readTerms(num_free, depth);
        errdefer deinitTerms(free_vars, self.allocator);
        if (self.pos != expected_end) return error.InvalidFun;
        return .{ .new_fun = .{
            .arity = arity,
            .uniq = uniq,
            .index = index,
            .module = module,
            .old_index = old_index,
            .old_uniq = old_uniq,
            .pid = pid,
            .free_vars = free_vars,
        } };
    }

    fn readLegacyFun(self: *Decoder, depth: usize) DecodeError!Term {
        const num_free = try self.readU32();
        const pid_term = try self.readTerm(depth + 1, false);
        const pid = switch (pid_term) {
            .pid => |v| v,
            else => {
                var invalid = pid_term;
                invalid.deinit(self.allocator);
                return error.InvalidFun;
            },
        };
        errdefer self.allocator.free(pid.node);
        const module = try self.readAtom(depth);
        errdefer self.allocator.free(module);
        const index = try self.readI32Term(depth);
        const uniq = try self.readI32Term(depth);
        const free_vars = try self.readTerms(num_free, depth);
        return .{ .legacy_fun = .{
            .pid = pid,
            .module = module,
            .index = index,
            .uniq = uniq,
            .free_vars = free_vars,
        } };
    }

    fn readExport(self: *Decoder, depth: usize) DecodeError!Term {
        const module = try self.readAtom(depth);
        errdefer self.allocator.free(module);
        const function = try self.readAtom(depth);
        errdefer self.allocator.free(function);
        const arity_tag = try self.readByte();
        if (arity_tag != @intFromEnum(Tag.small_integer_ext)) return error.InvalidFun;
        return .{ .@"export" = .{ .module = module, .function = function, .arity = try self.readByte() } };
    }

    fn readRecord(self: *Decoder, depth: usize) DecodeError!Term {
        const count: usize = try self.readU32();
        try self.checkCollection(count);
        const flags = try self.readByte();
        if (flags & 0xfe != 0) return error.InvalidRecord;
        const module = try self.readAtom(depth);
        errdefer self.allocator.free(module);
        const name = try self.readAtom(depth);
        errdefer self.allocator.free(name);
        const names = self.allocator.alloc([]u8, count) catch return error.OutOfMemory;
        var names_initialized: usize = 0;
        errdefer {
            for (names[0..names_initialized]) |field_name| self.allocator.free(field_name);
            self.allocator.free(names);
        }
        for (names) |*field_name| {
            field_name.* = try self.readAtom(depth);
            names_initialized += 1;
        }
        const values = try self.readTerms(count, depth);
        return .{ .record = .{
            .exported = flags & 1 != 0,
            .module = module,
            .name = name,
            .field_names = names,
            .values = values,
        } };
    }

    fn readI32Term(self: *Decoder, depth: usize) DecodeError!i32 {
        var value = try self.readTerm(depth + 1, false);
        defer value.deinit(self.allocator);
        return switch (value) {
            .integer => |v| std.math.cast(i32, v) orelse error.Overflow,
            else => error.InvalidFun,
        };
    }

    fn readAtom(self: *Decoder, depth: usize) DecodeError![]u8 {
        const value = try self.readTerm(depth + 1, false);
        return switch (value) {
            .atom => |atom| atom,
            else => {
                var invalid = value;
                invalid.deinit(self.allocator);
                return error.InvalidAtom;
            },
        };
    }

    fn readUtf8Atom(self: *Decoder, count: usize) DecodeError![]u8 {
        const raw = try self.readSlice(count);
        if (!std.unicode.utf8ValidateSlice(raw)) return error.InvalidAtom;
        const codepoints = std.unicode.utf8CountCodepoints(raw) catch return error.InvalidAtom;
        if (codepoints > 255) return error.AtomTooLong;
        return self.allocator.dupe(u8, raw) catch return error.OutOfMemory;
    }

    fn readLatin1Atom(self: *Decoder, count: usize) DecodeError![]u8 {
        if (count > 255) return error.AtomTooLong;
        const raw = try self.readSlice(count);
        var utf8_len: usize = 0;
        for (raw) |byte| utf8_len += if (byte < 0x80) 1 else 2;
        const out = self.allocator.alloc(u8, utf8_len) catch return error.OutOfMemory;
        var pos: usize = 0;
        for (raw) |byte| {
            if (byte < 0x80) {
                out[pos] = byte;
                pos += 1;
            } else {
                out[pos] = 0xc0 | (byte >> 6);
                out[pos + 1] = 0x80 | (byte & 0x3f);
                pos += 2;
            }
        }
        return out;
    }

    fn readCachedAtom(self: *Decoder) DecodeError![]u8 {
        const index = try self.readByte();
        const cache = self.options.atom_cache orelse return error.MissingAtomCache;
        if (index >= cache.len) return error.InvalidAtomCacheRef;
        const atom = cache[index];
        if (!std.unicode.utf8ValidateSlice(atom)) return error.InvalidAtom;
        if ((std.unicode.utf8CountCodepoints(atom) catch return error.InvalidAtom) > 255) return error.AtomTooLong;
        return self.allocator.dupe(u8, atom) catch return error.OutOfMemory;
    }

    fn checkCollection(self: *Decoder, count: usize) DecodeError!void {
        if (count > self.options.max_collection_elements) return error.CollectionLimit;
    }

    fn readOwned(self: *Decoder, count: usize) DecodeError![]u8 {
        if (count > self.options.max_uncompressed_size) return error.SizeLimit;
        const raw = try self.readSlice(count);
        return self.allocator.dupe(u8, raw) catch return error.OutOfMemory;
    }

    fn readByte(self: *Decoder) DecodeError!u8 {
        if (self.pos >= self.input.len) return error.UnexpectedEof;
        const byte = self.input[self.pos];
        self.pos += 1;
        return byte;
    }

    fn readSlice(self: *Decoder, count: usize) DecodeError![]const u8 {
        const end = std.math.add(usize, self.pos, count) catch return error.Overflow;
        if (end > self.input.len) return error.UnexpectedEof;
        const out = self.input[self.pos..end];
        self.pos = end;
        return out;
    }

    fn readU16(self: *Decoder) DecodeError!u16 {
        const bytes = try self.readSlice(2);
        return std.mem.readInt(u16, bytes[0..2], .big);
    }

    fn readU32(self: *Decoder) DecodeError!u32 {
        const bytes = try self.readSlice(4);
        return std.mem.readInt(u32, bytes[0..4], .big);
    }

    fn readSigned32(self: *Decoder) DecodeError!i32 {
        return @bitCast(try self.readU32());
    }

    fn readU64(self: *Decoder) DecodeError!u64 {
        const bytes = try self.readSlice(8);
        return std.mem.readInt(u64, bytes[0..8], .big);
    }
};

const Encoder = struct {
    allocator: std.mem.Allocator,
    writer: *compat.Io.Writer,
    options: EncodeOptions,

    fn writeTerm(self: *Encoder, term: Term, depth: usize, top_level: bool) EncodeError!void {
        if (depth >= self.options.max_depth) return error.DepthLimit;
        switch (term) {
            .integer => |value| try self.writeInteger(value),
            .big_integer => |value| try self.writeBig(value.negative, value.magnitude),
            .float => |value| {
                if (!std.math.isFinite(value)) return error.InvalidFloat;
                try self.byte(.new_float_ext);
                try self.int(u64, @bitCast(value));
            },
            .atom => |value| try self.writeAtom(value),
            .pid => |value| try self.writePid(value, depth),
            .port => |value| try self.writePort(value, depth),
            .reference => |value| try self.writeReference(value, depth),
            .tuple => |items| {
                try self.checkCollection(items.len);
                if (items.len <= std.math.maxInt(u8)) {
                    try self.byte(.small_tuple_ext);
                    self.writer.writeByte(@intCast(items.len)) catch return error.WriteFailed;
                } else {
                    try self.byte(.large_tuple_ext);
                    try self.length(items.len);
                }
                try self.writeTerms(items, depth);
            },
            .map => |entries| {
                try self.checkCollection(entries.len);
                var dedup = try MapKeyDedup.init(self.allocator, entries.len, @intFromPtr(entries.ptr));
                defer dedup.deinit(self.allocator);
                for (entries, 0..) |_, i| try dedup.add(entries, i);
                try self.byte(.map_ext);
                try self.length(entries.len);
                for (entries) |entry| {
                    try self.writeTerm(entry.key, depth + 1, false);
                    try self.writeTerm(entry.value, depth + 1, false);
                }
            },
            .nil => try self.byte(.nil_ext),
            .list => |value| {
                try self.checkCollection(value.elements.len);
                if (value.elements.len == 0 and value.tail == null) {
                    try self.byte(.nil_ext);
                    return;
                }
                try self.byte(.list_ext);
                try self.length(value.elements.len);
                try self.writeTerms(value.elements, depth);
                if (value.tail) |tail| try self.writeTerm(tail.*, depth + 1, false) else try self.byte(.nil_ext);
            },
            .binary => |value| {
                try self.byte(.binary_ext);
                try self.length(value.len);
                self.writer.writeAll(value) catch return error.WriteFailed;
            },
            .bit_binary => |value| {
                if (value.bytes.len == 0 or value.bits < 1 or value.bits > 8) return error.InvalidTerm;
                if (value.bits < 8) {
                    const unused: u3 = @intCast(8 - value.bits);
                    const mask: u8 = (@as(u8, 1) << unused) - 1;
                    if (value.bytes[value.bytes.len - 1] & mask != 0) return error.InvalidTerm;
                }
                try self.byte(.bit_binary_ext);
                try self.length(value.bytes.len);
                self.writer.writeByte(@intCast(value.bits)) catch return error.WriteFailed;
                self.writer.writeAll(value.bytes) catch return error.WriteFailed;
            },
            .new_fun => |value| try self.writeNewFun(value, depth),
            .legacy_fun => |value| try self.writeLegacyFun(value, depth),
            .@"export" => |value| {
                try self.checkChildDepth(depth);
                try self.byte(.export_ext);
                try self.writeAtom(value.module);
                try self.writeAtom(value.function);
                try self.byte(.small_integer_ext);
                self.writer.writeByte(value.arity) catch return error.WriteFailed;
            },
            .record => |value| try self.writeRecord(value, depth),
            .local => |value| {
                if (!top_level) return error.InvalidTerm;
                if (!self.options.allow_local) return error.LocalDisabled;
                try self.byte(.local_ext);
                self.writer.writeAll(value) catch return error.WriteFailed;
            },
        }
    }

    fn writeInteger(self: *Encoder, value: i64) EncodeError!void {
        if (value >= 0 and value <= 255) {
            try self.byte(.small_integer_ext);
            self.writer.writeByte(@intCast(value)) catch return error.WriteFailed;
        } else if (value >= std.math.minInt(i32) and value <= std.math.maxInt(i32)) {
            try self.byte(.integer_ext);
            try self.int(u32, @bitCast(@as(i32, @intCast(value))));
        } else {
            var bytes: [8]u8 = undefined;
            var magnitude: u64 = if (value == std.math.minInt(i64)) (@as(u64, 1) << 63) else @intCast(if (value < 0) -value else value);
            var count: usize = 0;
            while (magnitude != 0) : (magnitude >>= 8) {
                bytes[count] = @truncate(magnitude);
                count += 1;
            }
            try self.writeBig(value < 0, bytes[0..count]);
        }
    }

    fn writeBig(self: *Encoder, negative: bool, raw_magnitude: []const u8) EncodeError!void {
        var count = raw_magnitude.len;
        while (count > 0 and raw_magnitude[count - 1] == 0) count -= 1;
        if (count > self.options.max_bignum_bytes) return error.SizeLimit;
        if (count == 0) return self.writeInteger(0);
        if (count <= 8) {
            var magnitude: u64 = 0;
            for (raw_magnitude[0..count], 0..) |digit, i| magnitude |= @as(u64, digit) << @intCast(i * 8);
            if (!negative and magnitude <= std.math.maxInt(i32)) return self.writeInteger(@intCast(magnitude));
            if (negative and magnitude <= @as(u64, -@as(i64, std.math.minInt(i32))))
                return self.writeInteger(-@as(i64, @intCast(magnitude)));
        }
        if (count <= std.math.maxInt(u8)) {
            try self.byte(.small_big_ext);
            self.writer.writeByte(@intCast(count)) catch return error.WriteFailed;
        } else {
            try self.byte(.large_big_ext);
            try self.length(count);
        }
        self.writer.writeByte(@intFromBool(negative)) catch return error.WriteFailed;
        self.writer.writeAll(raw_magnitude[0..count]) catch return error.WriteFailed;
    }

    fn writeAtom(self: *Encoder, atom: []const u8) EncodeError!void {
        if (!std.unicode.utf8ValidateSlice(atom)) return error.InvalidAtom;
        const codepoints = std.unicode.utf8CountCodepoints(atom) catch return error.InvalidAtom;
        if (codepoints > 255) return error.AtomTooLong;
        if (self.options.atom_cache) |cache| {
            for (cache, 0..) |cached, i| {
                if (i >= 255) break;
                if (std.mem.eql(u8, atom, cached)) {
                    try self.byte(.atom_cache_ref);
                    self.writer.writeByte(@intCast(i)) catch return error.WriteFailed;
                    return;
                }
            }
        }
        if (atom.len <= std.math.maxInt(u8)) {
            try self.byte(.small_atom_utf8_ext);
            self.writer.writeByte(@intCast(atom.len)) catch return error.WriteFailed;
        } else if (atom.len <= std.math.maxInt(u16)) {
            try self.byte(.atom_utf8_ext);
            try self.int(u16, @intCast(atom.len));
        } else return error.AtomTooLong;
        self.writer.writeAll(atom) catch return error.WriteFailed;
    }

    fn writePid(self: *Encoder, value: term_mod.Pid, depth: usize) EncodeError!void {
        try self.checkChildDepth(depth);
        try self.byte(.new_pid_ext);
        try self.writeAtom(value.node);
        try self.int(u32, value.id);
        try self.int(u32, value.serial);
        try self.int(u32, value.creation);
    }

    fn writePort(self: *Encoder, value: term_mod.Port, depth: usize) EncodeError!void {
        try self.checkChildDepth(depth);
        if (value.id <= 0x0fffffff) {
            try self.byte(.new_port_ext);
            try self.writeAtom(value.node);
            try self.int(u32, @intCast(value.id));
        } else {
            try self.byte(.v4_port_ext);
            try self.writeAtom(value.node);
            try self.int(u64, value.id);
        }
        try self.int(u32, value.creation);
    }

    fn writeReference(self: *Encoder, value: term_mod.Reference, depth: usize) EncodeError!void {
        try self.checkChildDepth(depth);
        if (value.ids.len == 0 or value.ids.len > 5) return error.InvalidTerm;
        try self.byte(.newer_reference_ext);
        try self.int(u16, @intCast(value.ids.len));
        try self.writeAtom(value.node);
        try self.int(u32, value.creation);
        for (value.ids) |id| try self.int(u32, id);
    }

    fn writeNewFun(self: *Encoder, value: term_mod.NewFun, depth: usize) EncodeError!void {
        try self.checkChildDepth(depth);
        try self.checkCollection(value.free_vars.len);
        var aw: compat.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();
        var nested = Encoder{ .allocator = self.allocator, .writer = &aw.writer, .options = self.options };
        aw.writer.writeByte(value.arity) catch return error.WriteFailed;
        aw.writer.writeAll(&value.uniq) catch return error.WriteFailed;
        try nested.int(u32, value.index);
        try nested.length(value.free_vars.len);
        try nested.writeAtom(value.module);
        try nested.writeInteger(value.old_index);
        try nested.writeInteger(value.old_uniq);
        try nested.writePid(value.pid, depth + 1);
        try nested.writeTerms(value.free_vars, depth);
        const size = std.math.add(usize, aw.writer.end, 4) catch return error.LengthOverflow;
        try self.byte(.new_fun_ext);
        try self.length(size);
        self.writer.writeAll(aw.writer.buffer[0..aw.writer.end]) catch return error.WriteFailed;
    }

    fn writeLegacyFun(self: *Encoder, value: term_mod.LegacyFun, depth: usize) EncodeError!void {
        if (!self.options.allow_legacy) return error.LegacyDisabled;
        if (value.pid.id > 0x7fff or value.pid.serial > 0x1fff or value.pid.creation > 3) return error.InvalidTerm;
        try self.checkChildDepth(depth);
        try self.checkCollection(value.free_vars.len);
        try self.byte(.fun_ext);
        try self.length(value.free_vars.len);
        try self.byte(.pid_ext);
        try self.writeAtom(value.pid.node);
        try self.int(u32, value.pid.id);
        try self.int(u32, value.pid.serial);
        self.writer.writeByte(@intCast(value.pid.creation)) catch return error.WriteFailed;
        try self.writeAtom(value.module);
        try self.writeInteger(value.index);
        try self.writeInteger(value.uniq);
        try self.writeTerms(value.free_vars, depth);
    }

    fn writeRecord(self: *Encoder, value: term_mod.Record, depth: usize) EncodeError!void {
        if (value.field_names.len != value.values.len) return error.InvalidTerm;
        try self.checkChildDepth(depth);
        try self.checkCollection(value.values.len);
        try self.byte(.record_ext);
        try self.length(value.values.len);
        self.writer.writeByte(@intFromBool(value.exported)) catch return error.WriteFailed;
        try self.writeAtom(value.module);
        try self.writeAtom(value.name);
        for (value.field_names) |name| try self.writeAtom(name);
        try self.writeTerms(value.values, depth);
    }

    fn writeTerms(self: *Encoder, terms: []const Term, depth: usize) EncodeError!void {
        for (terms) |term| try self.writeTerm(term, depth + 1, false);
    }

    fn checkCollection(self: *Encoder, count: usize) EncodeError!void {
        if (count > self.options.max_collection_elements) return error.SizeLimit;
    }

    fn checkChildDepth(self: *Encoder, depth: usize) EncodeError!void {
        if (depth + 1 >= self.options.max_depth) return error.DepthLimit;
    }

    fn length(self: *Encoder, value: usize) EncodeError!void {
        if (value > std.math.maxInt(u32)) return error.LengthOverflow;
        try self.int(u32, @intCast(value));
    }

    fn byte(self: *Encoder, tag: Tag) EncodeError!void {
        self.writer.writeByte(@intFromEnum(tag)) catch return error.WriteFailed;
    }

    fn int(self: *Encoder, comptime T: type, value: T) EncodeError!void {
        writeInt(self.writer, T, value) catch return error.WriteFailed;
    }
};

fn writeInt(writer: *compat.Io.Writer, comptime T: type, value: T) !void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .big);
    try writer.writeAll(&bytes);
}

fn deinitTerms(items: []Term, allocator: std.mem.Allocator) void {
    for (items) |*item| item.deinit(allocator);
    allocator.free(items);
}

test "all scalar forms and canonical integer boundaries" {
    const allocator = std.testing.allocator;
    const cases = [_]Term{
        .{ .integer = 255 },
        .{ .integer = 256 },
        .{ .integer = std.math.minInt(i32) },
        .{ .integer = @as(i64, std.math.maxInt(i32)) + 1 },
        .{ .float = 1.25 },
        .{ .atom = @constCast("héllo") },
        .{ .binary = @constCast("bytes") },
    };
    for (cases) |item| {
        const encoded = try encodeTerm(allocator, item, .{});
        defer allocator.free(encoded);
        var decoded = try decodeTerm(allocator, encoded, .{});
        defer decoded.deinit(allocator);
        try std.testing.expect(item.eql(decoded));
    }
}

test "legacy Latin-1 atom normalizes to UTF-8" {
    const bytes = [_]u8{ version, @intFromEnum(Tag.small_atom_ext), 1, 0xe9 };
    var decoded = try decodeTerm(std.testing.allocator, &bytes, .{});
    defer decoded.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("é", decoded.atom);
}

test "large maps roundtrip and duplicate keys are rejected via the hash index" {
    const allocator = std.testing.allocator;
    const count = 100;

    var entries: [count]MapEntry = undefined;
    for (&entries, 0..) |*entry, i| {
        entry.* = .{ .key = .{ .integer = @intCast(i) }, .value = .{ .integer = @intCast(i * 2) } };
    }
    const valid = Term{ .map = &entries };
    const encoded = try encodeTerm(allocator, valid, .{});
    defer allocator.free(encoded);
    var decoded = try decodeTerm(allocator, encoded, .{});
    defer decoded.deinit(allocator);
    try std.testing.expect(valid.eql(decoded));

    var duplicate_entries: [count]MapEntry = entries;
    duplicate_entries[count - 1].key = duplicate_entries[0].key;
    const duplicate = Term{ .map = &duplicate_entries };
    try std.testing.expectError(error.DuplicateMapKey, encodeTerm(allocator, duplicate, .{}));

    var wire: compat.Io.Writer.Allocating = .init(allocator);
    defer wire.deinit();
    try wire.writer.writeAll(&.{ version, @intFromEnum(Tag.map_ext), 0, 0, 0, count });
    for (0..count) |i| {
        const key: u8 = if (i + 1 == count) 0 else @intCast(i);
        try wire.writer.writeAll(&.{ @intFromEnum(Tag.small_integer_ext), key, @intFromEnum(Tag.nil_ext) });
    }
    try std.testing.expectError(
        error.DuplicateMapKey,
        decodeTerm(allocator, wire.writer.buffer[0..wire.writer.end], .{}),
    );
}

test "compressed ETF roundtrip" {
    const allocator = std.testing.allocator;
    const input = Term{ .binary = @constCast("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") };
    const encoded = try encodeTerm(allocator, input, .{ .compression = .always });
    defer allocator.free(encoded);
    try std.testing.expectEqual(@as(u8, 80), encoded[1]);
    var decoded = try decodeTerm(allocator, encoded, .{});
    defer decoded.deinit(allocator);
    try std.testing.expect(input.eql(decoded));
}
