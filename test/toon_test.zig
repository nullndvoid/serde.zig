const std = @import("std");
const testing = std.testing;
const serde = @import("serde");

test "toon encode primitives and object fields" {
    const Config = struct {
        id: u32,
        name: []const u8,
        active: bool,
        missing: ?[]const u8 = null,
    };

    const bytes = try serde.toon.toSlice(testing.allocator, Config{
        .id = 123,
        .name = "Ada Lovelace",
        .active = true,
        .missing = null,
    });
    defer testing.allocator.free(bytes);

    try testing.expectEqualStrings(
        "id: 123\nname: Ada Lovelace\nactive: true\nmissing: null",
        bytes,
    );
}

test "toon decode root primitives" {
    try testing.expectEqual(true, try serde.toon.fromSlice(bool, testing.allocator, "true"));
    try testing.expectEqual(@as(i32, -42), try serde.toon.fromSlice(i32, testing.allocator, "-42"));

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const s = try serde.toon.fromSlice([]const u8, arena.allocator(), "\"123\"");
    try testing.expectEqualStrings("123", s);
}

test "toon encode and decode primitive arrays" {
    const Root = struct { tags: []const []const u8 };
    const tags: []const []const u8 = &.{ "admin", "ops", "dev" };
    const bytes = try serde.toon.toSlice(testing.allocator, Root{ .tags = tags });
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings("tags[3]: admin,ops,dev", bytes);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const root = try serde.toon.fromSlice(Root, arena.allocator(), bytes);
    try testing.expectEqual(@as(usize, 3), root.tags.len);
    try testing.expectEqualStrings("ops", root.tags[1]);
}

test "toon encode and decode tabular arrays" {
    const Item = struct { id: u32, name: []const u8, active: bool };
    const Root = struct { items: []const Item };
    const items: []const Item = &.{
        .{ .id = 1, .name = "Ada", .active = true },
        .{ .id = 2, .name = "Bob", .active = false },
    };

    const bytes = try serde.toon.toSlice(testing.allocator, Root{ .items = items });
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        "items[2]{id,name,active}:\n  1,Ada,true\n  2,Bob,false",
        bytes,
    );

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const root = try serde.toon.fromSlice(Root, arena.allocator(), bytes);
    try testing.expectEqual(@as(usize, 2), root.items.len);
    try testing.expectEqualStrings("Bob", root.items[1].name);
    try testing.expectEqual(false, root.items[1].active);
}

test "toon delimiters and quoting" {
    const Root = struct { tags: []const []const u8 };
    const tags: []const []const u8 = &.{ "a,b", "c|d", "line\nbreak" };
    const bytes = try serde.toon.toSliceWith(testing.allocator, Root{ .tags = tags }, .{ .delimiter = .pipe });
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings("tags[3|]: a,b|\"c|d\"|\"line\\nbreak\"", bytes);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const root = try serde.toon.fromSlice(Root, arena.allocator(), bytes);
    try testing.expectEqualStrings("a,b", root.tags[0]);
    try testing.expectEqualStrings("c|d", root.tags[1]);
    try testing.expectEqualStrings("line\nbreak", root.tags[2]);
}

test "toon schema rename roundtrip" {
    const Config = struct {
        service_name: []const u8,
        port_number: u16,
    };
    const schema = .{ .rename_all = serde.NamingConvention.kebab_case };
    const bytes = try serde.toon.toSliceSchema(testing.allocator, Config{
        .service_name = "api",
        .port_number = 8080,
    }, schema);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings("\"service-name\": api\n\"port-number\": 8080", bytes);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const parsed = try serde.toon.fromSliceSchema(Config, arena.allocator(), bytes, schema);
    try testing.expectEqualStrings("api", parsed.service_name);
    try testing.expectEqual(@as(u16, 8080), parsed.port_number);
}

test "toon key folding and path expansion" {
    const Root = struct { a: struct { b: struct { c: u32 } } };
    const bytes = try serde.toon.toSliceWith(testing.allocator, Root{ .a = .{ .b = .{ .c = 1 } } }, .{
        .key_folding = .safe,
    });
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings("a.b.c: 1", bytes);

    const parsed = try serde.toon.fromSliceWith(Root, testing.allocator, bytes, .{ .expand_paths = .safe });
    try testing.expectEqual(@as(u32, 1), parsed.a.b.c);
}

test "toon strict duplicate keys and count mismatch" {
    const Root = struct { a: u32 };
    try testing.expectError(error.DuplicateKey, serde.toon.fromSlice(Root, testing.allocator, "a: 1\na: 2"));

    const Arr = struct { tags: []const []const u8 };
    try testing.expectError(error.CountMismatch, serde.toon.fromSlice(Arr, testing.allocator, "tags[3]: a,b"));
}

test "toon quoted dotted keys do not expand" {
    const value = try serde.toon.parse(testing.allocator, "\"a.b\": 1", .{ .expand_paths = .safe });
    defer value.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), value.object.len);
    try testing.expectEqualStrings("a.b", value.object[0].key);
    try testing.expectEqual(serde.toon.Value{ .uint = 1 }, value.object[0].value);
}
