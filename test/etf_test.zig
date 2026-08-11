const std = @import("std");
const serde = @import("serde");
const etf = serde.etf;

test "canonical typed ETF golden bytes" {
    const allocator = std.testing.allocator;

    const boolean = try etf.toSlice(allocator, true);
    defer allocator.free(boolean);
    try std.testing.expectEqualSlices(u8, &.{ 131, 119, 4, 't', 'r', 'u', 'e' }, boolean);

    const string = try etf.toSlice(allocator, @as([]const u8, "ok"));
    defer allocator.free(string);
    try std.testing.expectEqualSlices(u8, &.{ 131, 109, 0, 0, 0, 2, 'o', 'k' }, string);

    const list = try etf.toSlice(allocator, [_]u16{ 255, 256 });
    defer allocator.free(list);
    try std.testing.expectEqualSlices(u8, &.{ 131, 108, 0, 0, 0, 2, 97, 255, 98, 0, 0, 1, 0, 106 }, list);
}

test "typed schema, integer-key map, enum, and union rules" {
    const allocator = std.testing.allocator;
    const Point = struct { x: i32, y: i32 };
    const schema = .{ .rename = .{ .x = "X", .y = "Y" } };
    const point_bytes = try etf.toSliceSchema(allocator, Point{ .x = 1, .y = 2 }, schema);
    defer allocator.free(point_bytes);
    const point = try etf.fromSliceSchema(Point, allocator, point_bytes, schema);
    try std.testing.expectEqual(@as(i32, 1), point.x);
    try std.testing.expectEqual(@as(i32, 2), point.y);

    var source = std.AutoHashMap(u32, i32).init(allocator);
    defer source.deinit();
    try source.put(7, -9);
    const map_bytes = try etf.toSlice(allocator, source);
    defer allocator.free(map_bytes);
    var decoded = try etf.fromSlice(std.AutoHashMap(u32, i32), allocator, map_bytes);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(?i32, -9), decoded.get(7));

    const Color = enum { red, green };
    const color_bytes = try etf.toSlice(allocator, Color.green);
    defer allocator.free(color_bytes);
    try std.testing.expectEqual(Color.green, try etf.fromSlice(Color, allocator, color_bytes));

    const Command = union(enum) { ping: void, add: i32 };
    const command_bytes = try etf.toSlice(allocator, Command{ .add = 42 });
    defer allocator.free(command_bytes);
    const command = try etf.fromSlice(Command, allocator, command_bytes);
    try std.testing.expect(command == .add);
    try std.testing.expectEqual(@as(i32, 42), command.add);
}

test "typed writer, reader, collection, and depth limits" {
    const allocator = std.testing.allocator;
    const Point = struct { x: i32, y: i32 };
    const schema = .{ .rename = .{ .x = "X", .y = "Y" } };
    var storage: [128]u8 = undefined;
    var writer: serde.compat.Io.Writer = .fixed(&storage);
    try etf.toWriterWithSchema(allocator, &writer, Point{ .x = 3, .y = 4 }, .{}, schema);
    var reader: serde.compat.Io.Reader = .fixed(storage[0..writer.end]);
    const point = try etf.fromReaderWithSchema(Point, allocator, &reader, .{}, schema);
    try std.testing.expectEqual(@as(i32, 3), point.x);
    try std.testing.expectEqual(@as(i32, 4), point.y);

    const nested = [_][1]u8{.{1}};
    try std.testing.expectError(error.DepthLimit, etf.toSliceWith(allocator, nested, .{ .max_depth = 1 }));
    const nested_bytes = try etf.toSlice(allocator, nested);
    defer allocator.free(nested_bytes);
    try std.testing.expectError(error.DepthLimit, etf.fromSliceWith([1][1]u8, allocator, nested_bytes, .{ .max_depth = 1 }));
    try std.testing.expectError(error.SizeLimit, etf.toSliceWith(allocator, [_]u8{ 1, 2 }, .{ .max_collection_elements = 1 }));

    const wide_unsigned: u256 = (@as(u256, 1) << 200) | 0xdeadbeef;
    const wide_bytes = try etf.toSlice(allocator, wide_unsigned);
    defer allocator.free(wide_bytes);
    try std.testing.expectEqual(wide_unsigned, try etf.fromSlice(u256, allocator, wide_bytes));
    const wide_signed: i257 = -(@as(i257, 1) << 200);
    const signed_bytes = try etf.toSlice(allocator, wide_signed);
    defer allocator.free(signed_bytes);
    try std.testing.expectEqual(wide_signed, try etf.fromSlice(i257, allocator, signed_bytes));
}

test "Term roundtrips process identities, improper list, record, funs, and local" {
    const allocator = std.testing.allocator;
    var tail = etf.Term{ .atom = @constCast("tail") };
    var ref_ids = [_]u32{ 1, 0xffffffff };
    var list_items = [_]etf.Term{ .{ .integer = 1 }, .{ .binary = @constCast("two") } };
    var tuple_items = [_]etf.Term{
        .{ .pid = .{ .node = @constCast("n@h"), .id = 0xffffffff, .serial = 3, .creation = 4 } },
        .{ .port = .{ .node = @constCast("n@h"), .id = @as(u64, 1) << 40, .creation = 7 } },
        .{ .reference = .{ .node = @constCast("n@h"), .creation = 9, .ids = &ref_ids } },
        .{ .list = .{ .elements = &list_items, .tail = &tail } },
    };
    const composite = etf.Term{ .tuple = &tuple_items };
    const encoded = try etf.encodeTerm(allocator, composite, .{});
    defer allocator.free(encoded);
    var decoded = try etf.decodeTerm(allocator, encoded, .{});
    defer decoded.deinit(allocator);
    try std.testing.expect(composite.eql(decoded));

    var field_names = [_][]u8{ @constCast("x"), @constCast("y") };
    var values = [_]etf.Term{ .{ .integer = 1 }, .{ .atom = @constCast("ok") } };
    const record = etf.Term{ .record = .{
        .exported = true,
        .module = @constCast("m"),
        .name = @constCast("point"),
        .field_names = &field_names,
        .values = &values,
    } };
    const record_bytes = try etf.encodeTerm(allocator, record, .{});
    defer allocator.free(record_bytes);
    try std.testing.expectEqual(@as(u8, 67), record_bytes[1]);
    var decoded_record = try etf.decodeTerm(allocator, record_bytes, .{});
    defer decoded_record.deinit(allocator);
    try std.testing.expect(record.eql(decoded_record));

    var free_vars = [_]etf.Term{.{ .integer = 42 }};
    const pid = etf.Pid{ .node = @constCast("n@h"), .id = 1, .serial = 2, .creation = 3 };
    const new_fun = etf.Term{ .new_fun = .{
        .arity = 1,
        .uniq = @splat(0xab),
        .index = 5,
        .module = @constCast("m"),
        .old_index = 6,
        .old_uniq = 7,
        .pid = pid,
        .free_vars = &free_vars,
    } };
    const fun_bytes = try etf.encodeTerm(allocator, new_fun, .{});
    defer allocator.free(fun_bytes);
    var decoded_fun = try etf.decodeTerm(allocator, fun_bytes, .{});
    defer decoded_fun.deinit(allocator);
    try std.testing.expect(new_fun.eql(decoded_fun));

    const legacy_fun = etf.Term{ .legacy_fun = .{
        .pid = pid,
        .module = @constCast("m"),
        .index = 1,
        .uniq = 2,
        .free_vars = &free_vars,
    } };
    try std.testing.expectError(error.LegacyDisabled, etf.encodeTerm(allocator, legacy_fun, .{}));
    const legacy_bytes = try etf.encodeTerm(allocator, legacy_fun, .{ .allow_legacy = true });
    defer allocator.free(legacy_bytes);
    var decoded_legacy = try etf.decodeTerm(allocator, legacy_bytes, .{});
    defer decoded_legacy.deinit(allocator);
    try std.testing.expect(legacy_fun.eql(decoded_legacy));

    const local = etf.Term{ .local = @constCast("opaque-local-payload") };
    try std.testing.expectError(error.LocalDisabled, etf.encodeTerm(allocator, local, .{}));
    const local_bytes = try etf.encodeTerm(allocator, local, .{ .allow_local = true });
    defer allocator.free(local_bytes);
    var decoded_local = try etf.decodeTerm(allocator, local_bytes, .{});
    defer decoded_local.deinit(allocator);
    try std.testing.expect(local.eql(decoded_local));
}

test "wire boundary tags and adversarial validation" {
    const allocator = std.testing.allocator;

    var atom255: [255]u8 = @splat('a');
    const small_atom = try etf.encodeTerm(allocator, .{ .atom = &atom255 }, .{});
    defer allocator.free(small_atom);
    try std.testing.expectEqual(@as(u8, 119), small_atom[1]);

    var atom256: [256]u8 = @splat('a');
    atom256[254] = 0xc3;
    atom256[255] = 0xa9;
    const large_atom = try etf.encodeTerm(allocator, .{ .atom = &atom256 }, .{});
    defer allocator.free(large_atom);
    try std.testing.expectEqual(@as(u8, 118), large_atom[1]);

    const duplicate_map = [_]u8{
        131, 116, 0,  0, 0,  2,
        97,  1,   97, 2, 97, 1,
        97,  3,
    };
    try std.testing.expectError(error.DuplicateMapKey, etf.decodeTerm(allocator, &duplicate_map, .{}));

    const bad_bits = [_]u8{ 131, 77, 0, 0, 0, 1, 3, 0xff };
    try std.testing.expectError(error.InvalidBitBinary, etf.decodeTerm(allocator, &bad_bits, .{}));

    const missing_cache = [_]u8{ 131, 82, 0 };
    try std.testing.expectError(error.MissingAtomCache, etf.decodeTerm(allocator, &missing_cache, .{}));

    const oversized_compressed = [_]u8{ 131, 80, 0, 0, 1, 0 };
    try std.testing.expectError(error.SizeLimit, etf.decodeTerm(allocator, &oversized_compressed, .{ .max_uncompressed_size = 255 }));

    const legacy_reference = [_]u8{
        131, 101, 115, 3,  'n', '@', 'h',
        0,   0,   0,   42, 2,
    };
    var reference = try etf.decodeTerm(allocator, &legacy_reference, .{});
    defer reference.deinit(allocator);
    try std.testing.expect(reference == .reference);
    try std.testing.expectEqual(@as(u32, 42), reference.reference.ids[0]);
    try std.testing.expectEqual(@as(u32, 2), reference.reference.creation);
}

test "tuple, bignum, binary, atom, bit-binary, and export boundaries" {
    const allocator = std.testing.allocator;

    const tuple255 = try allocator.alloc(etf.Term, 255);
    defer allocator.free(tuple255);
    @memset(tuple255, .nil);
    const tuple255_bytes = try etf.encodeTerm(allocator, .{ .tuple = tuple255 }, .{});
    defer allocator.free(tuple255_bytes);
    try std.testing.expectEqual(@as(u8, 104), tuple255_bytes[1]);

    const tuple256 = try allocator.alloc(etf.Term, 256);
    defer allocator.free(tuple256);
    @memset(tuple256, .nil);
    const tuple256_bytes = try etf.encodeTerm(allocator, .{ .tuple = tuple256 }, .{});
    defer allocator.free(tuple256_bytes);
    try std.testing.expectEqual(@as(u8, 105), tuple256_bytes[1]);

    const magnitude255 = try allocator.alloc(u8, 255);
    defer allocator.free(magnitude255);
    @memset(magnitude255, 0);
    magnitude255[254] = 1;
    const small_big = try etf.encodeTerm(allocator, .{ .big_integer = .{ .negative = false, .magnitude = magnitude255 } }, .{});
    defer allocator.free(small_big);
    try std.testing.expectEqual(@as(u8, 110), small_big[1]);

    const magnitude256 = try allocator.alloc(u8, 256);
    defer allocator.free(magnitude256);
    @memset(magnitude256, 0);
    magnitude256[255] = 1;
    const large_big = try etf.encodeTerm(allocator, .{ .big_integer = .{ .negative = true, .magnitude = magnitude256 } }, .{});
    defer allocator.free(large_big);
    try std.testing.expectEqual(@as(u8, 111), large_big[1]);
    var decoded_big = try etf.decodeTerm(allocator, large_big, .{});
    defer decoded_big.deinit(allocator);
    try std.testing.expect(decoded_big == .big_integer);
    try std.testing.expect(decoded_big.big_integer.negative);
    try std.testing.expectEqualSlices(u8, magnitude256, decoded_big.big_integer.magnitude);

    const binary65535 = try allocator.alloc(u8, 65535);
    defer allocator.free(binary65535);
    @memset(binary65535, 0x5a);
    const binary65535_bytes = try etf.encodeTerm(allocator, .{ .binary = binary65535 }, .{});
    defer allocator.free(binary65535_bytes);
    try std.testing.expectEqual(@as(u32, 65535), std.mem.readInt(u32, binary65535_bytes[2..6], .big));
    const binary65536 = try allocator.alloc(u8, 65536);
    defer allocator.free(binary65536);
    @memset(binary65536, 0xa5);
    const binary65536_bytes = try etf.encodeTerm(allocator, .{ .binary = binary65536 }, .{});
    defer allocator.free(binary65536_bytes);
    try std.testing.expectEqual(@as(u32, 65536), std.mem.readInt(u32, binary65536_bytes[2..6], .big));

    var too_many_codepoints: [256]u8 = @splat('a');
    try std.testing.expectError(error.AtomTooLong, etf.encodeTerm(allocator, .{ .atom = &too_many_codepoints }, .{}));

    const bit_binary = etf.Term{ .bit_binary = .{ .bytes = @constCast(&[_]u8{0xf0}), .bits = 4 } };
    const bit_bytes = try etf.encodeTerm(allocator, bit_binary, .{});
    defer allocator.free(bit_bytes);
    var decoded_bits = try etf.decodeTerm(allocator, bit_bytes, .{});
    defer decoded_bits.deinit(allocator);
    try std.testing.expect(bit_binary.eql(decoded_bits));

    const export_term = etf.Term{ .@"export" = .{
        .module = @constCast("erlang"),
        .function = @constCast("length"),
        .arity = 1,
    } };
    const export_bytes = try etf.encodeTerm(allocator, export_term, .{});
    defer allocator.free(export_bytes);
    var decoded_export = try etf.decodeTerm(allocator, export_bytes, .{});
    defer decoded_export.deinit(allocator);
    try std.testing.expect(export_term.eql(decoded_export));

    const invalid_utf8 = [_]u8{ 131, 119, 1, 0xff };
    try std.testing.expectError(error.InvalidAtom, etf.decodeTerm(allocator, &invalid_utf8, .{}));
    const invalid_record_flags = [_]u8{ 131, 67, 0, 0, 0, 0, 2 };
    try std.testing.expectError(error.InvalidRecord, etf.decodeTerm(allocator, &invalid_record_flags, .{}));
    const invalid_fun_size = [_]u8{ 131, 112, 0, 0, 0, 3 };
    try std.testing.expectError(error.InvalidFun, etf.decodeTerm(allocator, &invalid_fun_size, .{}));
    try std.testing.expectError(error.InvalidVersion, etf.decodeTerm(allocator, &.{ 130, 106 }, .{}));
    try std.testing.expectError(error.TrailingData, etf.decodeTerm(allocator, &.{ 131, 106, 0 }, .{}));
}

test "compressed checksum and trailing bytes are rejected" {
    const allocator = std.testing.allocator;
    const encoded = try etf.encodeTerm(allocator, .{ .binary = @constCast("compress me") }, .{ .compression = .always });
    defer allocator.free(encoded);
    const corrupt = try allocator.dupe(u8, encoded);
    defer allocator.free(corrupt);
    corrupt[corrupt.len - 1] ^= 1;
    try std.testing.expectError(error.DecompressionFailed, etf.decodeTerm(allocator, corrupt, .{}));

    const trailing = try allocator.alloc(u8, encoded.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..encoded.len], encoded);
    trailing[encoded.len] = 0;
    try std.testing.expectError(error.DecompressionFailed, etf.decodeTerm(allocator, trailing, .{}));

    const typed = try etf.toSlice(allocator, @as([]const []const u8, &.{ "owned", "values" }));
    defer allocator.free(typed);
    const typed_trailing = try allocator.alloc(u8, typed.len + 1);
    defer allocator.free(typed_trailing);
    @memcpy(typed_trailing[0..typed.len], typed);
    typed_trailing[typed.len] = 0;
    try std.testing.expectError(error.TrailingData, etf.fromSlice([]const []const u8, allocator, typed_trailing));
}

test "unknown struct fields with nested payloads are skipped" {
    const allocator = std.testing.allocator;

    var free_vars = [_]etf.Term{.{ .big_integer = .{ .negative = true, .magnitude = @constCast(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9 }) } }};
    var improper_tail = etf.Term{ .atom = @constCast("tail") };
    var inner_entries = [_]etf.MapEntry{.{ .key = .{ .atom = @constCast("k") }, .value = .{ .float = 1.5 } }};
    var list_items = [_]etf.Term{ .{ .integer = 1 }, .{ .bit_binary = .{ .bytes = @constCast(&[_]u8{0xf0}), .bits = 4 } } };
    var extra_items = [_]etf.Term{
        .{ .pid = .{ .node = @constCast("n@h"), .id = 1, .serial = 2, .creation = 3 } },
        .{ .map = &inner_entries },
        .{ .list = .{ .elements = &list_items, .tail = &improper_tail } },
        .{ .new_fun = .{
            .arity = 0,
            .uniq = @splat(0x11),
            .index = 1,
            .module = @constCast("m"),
            .old_index = 0,
            .old_uniq = 0,
            .pid = .{ .node = @constCast("n@h"), .id = 1, .serial = 2, .creation = 3 },
            .free_vars = &free_vars,
        } },
    };
    var entries = [_]etf.MapEntry{
        .{ .key = .{ .binary = @constCast("a") }, .value = .{ .integer = 1 } },
        .{ .key = .{ .binary = @constCast("extra") }, .value = .{ .tuple = &extra_items } },
        .{ .key = .{ .binary = @constCast("b") }, .value = .{ .integer = 2 } },
    };
    const encoded = try etf.encodeTerm(allocator, .{ .map = &entries }, .{});
    defer allocator.free(encoded);

    const Value = struct { a: i64, b: i64 };
    const decoded = try etf.fromSlice(Value, allocator, encoded);
    try std.testing.expectEqual(@as(i64, 1), decoded.a);
    try std.testing.expectEqual(@as(i64, 2), decoded.b);
}

test "all OTP 29 control opcodes classify and preserve arguments" {
    const allocator = std.testing.allocator;
    const cases = [_]struct { opcode: u8, args: usize }{
        .{ .opcode = 1, .args = 2 },  .{ .opcode = 2, .args = 2 },  .{ .opcode = 3, .args = 3 },
        .{ .opcode = 4, .args = 2 },  .{ .opcode = 5, .args = 0 },  .{ .opcode = 6, .args = 3 },
        .{ .opcode = 7, .args = 2 },  .{ .opcode = 8, .args = 3 },  .{ .opcode = 12, .args = 3 },
        .{ .opcode = 13, .args = 4 }, .{ .opcode = 16, .args = 4 }, .{ .opcode = 18, .args = 4 },
        .{ .opcode = 19, .args = 3 }, .{ .opcode = 20, .args = 3 }, .{ .opcode = 21, .args = 4 },
        .{ .opcode = 22, .args = 2 }, .{ .opcode = 23, .args = 3 }, .{ .opcode = 24, .args = 2 },
        .{ .opcode = 25, .args = 3 }, .{ .opcode = 26, .args = 2 }, .{ .opcode = 27, .args = 3 },
        .{ .opcode = 28, .args = 3 }, .{ .opcode = 29, .args = 5 }, .{ .opcode = 30, .args = 6 },
        .{ .opcode = 31, .args = 4 }, .{ .opcode = 32, .args = 5 }, .{ .opcode = 33, .args = 2 },
        .{ .opcode = 34, .args = 3 }, .{ .opcode = 35, .args = 3 }, .{ .opcode = 36, .args = 3 },
        .{ .opcode = 37, .args = 3 },
    };
    for (cases) |case| {
        const tuple = try allocator.alloc(etf.Term, case.args + 1);
        tuple[0] = .{ .integer = case.opcode };
        for (tuple[1..]) |*arg| arg.* = .{ .integer = 0 };
        var control = try etf.distribution.ControlMessage.fromTerm(allocator, .{ .tuple = tuple });
        defer control.deinit(allocator);
        try std.testing.expect(control.opcode() != null);
        try std.testing.expectEqual(case.opcode, @intFromEnum(control.opcode().?));
        try std.testing.expectEqual(case.args, control.args().?.len);
    }

    var unknown_tuple = try allocator.alloc(etf.Term, 2);
    unknown_tuple[0] = .{ .integer = 99 };
    unknown_tuple[1] = .{ .atom = try allocator.dupe(u8, "future") };
    var unknown = try etf.distribution.ControlMessage.fromTerm(allocator, .{ .tuple = unknown_tuple });
    defer unknown.deinit(allocator);
    try std.testing.expect(unknown == .unknown);

    var bad_altact_tuple = try allocator.alloc(etf.Term, 4);
    bad_altact_tuple[0] = .{ .integer = 37 };
    bad_altact_tuple[1] = .{ .integer = 2 };
    bad_altact_tuple[2] = .{ .integer = 0 };
    bad_altact_tuple[3] = .{ .integer = 0 };
    var bad_altact = try etf.distribution.ControlMessage.fromTerm(allocator, .{ .tuple = bad_altact_tuple });
    defer bad_altact.deinit(allocator);
    try std.testing.expect(bad_altact == .unknown);
}

test "distribution pass-through compatibility and pinned cache eviction" {
    const allocator = std.testing.allocator;
    const dist = etf.distribution;

    const pass_through = [_]u8{ 0, 0, 0, 6, 112, 131, 104, 1, 97, 5 };
    var legacy_decoder = dist.Decoder.init(allocator, .{}, .{});
    defer legacy_decoder.deinit();
    try legacy_decoder.feed(&pass_through);
    var legacy_message = (try legacy_decoder.next()).?;
    defer legacy_message.deinit(allocator);
    try std.testing.expect(legacy_message == .data);
    try std.testing.expect(legacy_message.data.control == .node_link);

    const caps = dist.CapabilityFlags{
        .bits = dist.CapabilityFlags.dist_hdr_atom_cache | dist.CapabilityFlags.utf8_atoms,
    };
    var encoder = dist.Encoder.init(allocator, caps, .{});
    defer encoder.deinit();
    try encoder.cache.put(allocator, 2047, "old");
    encoder.next_slot = 2047;
    var payload_items = [_]etf.Term{
        .{ .atom = @constCast("old") },
        .{ .atom = @constCast("new") },
    };
    const empty_args = try allocator.alloc(etf.Term, 0);
    var control = dist.ControlMessage{ .node_link = .{ .terms = empty_args } };
    defer control.deinit(allocator);
    var frames = try encoder.encode(control, .{ .tuple = &payload_items });
    defer frames.deinit(allocator);
    try std.testing.expectEqualStrings("old", encoder.cache.get(2047).?);
    try std.testing.expectEqualStrings("new", encoder.cache.get(0).?);

    var invalid_items = [_]etf.Term{
        .{ .atom = @constCast("old") },
        .{ .atom = @constCast("staged") },
        .{ .float = std.math.nan(f64) },
    };
    encoder.next_slot = 1;
    try std.testing.expectError(error.InvalidFloat, encoder.encode(control, .{ .tuple = &invalid_items }));
    try std.testing.expect(encoder.cache.find("staged") == null);
    try std.testing.expectEqual(@as(u11, 1), encoder.next_slot);

    var long_atom: [256]u8 = @splat('a');
    long_atom[254] = 0xc3;
    long_atom[255] = 0xa9;
    var long_frames = try encoder.encode(control, .{ .atom = &long_atom });
    defer long_frames.deinit(allocator);
    var decoder = dist.Decoder.init(allocator, caps, .{});
    defer decoder.deinit();
    try decoder.feed(long_frames.items[0]);
    var long_message = (try decoder.next()).?;
    defer long_message.deinit(allocator);
    try std.testing.expectEqualStrings(&long_atom, long_message.data.payload.?.atom);
}

test "distribution fragmentation reassembles payload" {
    const allocator = std.testing.allocator;
    const caps = etf.distribution.CapabilityFlags{
        .bits = etf.distribution.CapabilityFlags.dist_hdr_atom_cache |
            etf.distribution.CapabilityFlags.utf8_atoms |
            etf.distribution.CapabilityFlags.fragments,
    };
    var encoder = etf.distribution.Encoder.init(allocator, caps, .{ .fragment_size = 80 });
    defer encoder.deinit();
    var decoder = etf.distribution.Decoder.init(allocator, caps, .{});
    defer decoder.deinit();

    const empty_args = try allocator.alloc(etf.Term, 0);
    var control = etf.distribution.ControlMessage{ .node_link = .{ .terms = empty_args } };
    defer control.deinit(allocator);
    var data: [400]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = @truncate(i);
    var frames = try encoder.encode(control, .{ .binary = &data });
    defer frames.deinit(allocator);
    try std.testing.expect(frames.items.len > 1);
    for (frames.items, 0..) |frame, i| {
        try decoder.feed(frame);
        const maybe = try decoder.next();
        if (i + 1 != frames.items.len) {
            try std.testing.expect(maybe == null);
        } else {
            var message = maybe.?;
            defer message.deinit(allocator);
            try std.testing.expect(message == .data);
            try std.testing.expect(message.data.payload != null);
            try std.testing.expectEqualSlices(u8, &data, message.data.payload.?.binary);
        }
    }
}
