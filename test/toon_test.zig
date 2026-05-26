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

test "toon strict arrays allow blank after completed count only" {
    const Root = struct {
        items: []const []const u8,
        next: u32,
    };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const parsed = try serde.toon.fromSlice(Root, arena.allocator(),
        \\items[2]:
        \\  - a
        \\  - b
        \\
        \\next: 1
    );
    try testing.expectEqual(@as(usize, 2), parsed.items.len);
    try testing.expectEqualStrings("b", parsed.items[1]);
    try testing.expectEqual(@as(u32, 1), parsed.next);

    try testing.expectError(error.InvalidSyntax, serde.toon.fromSlice(Root, testing.allocator,
        \\items[2]:
        \\  - a
        \\
        \\  - b
        \\next: 1
    ));

    var non_strict_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer non_strict_arena.deinit();
    const non_strict = try serde.toon.fromSliceWith(Root, non_strict_arena.allocator(),
        \\items[2]:
        \\  - a
        \\
        \\  - b
        \\next: 1
    , .{ .strict = false });
    try testing.expectEqual(@as(usize, 2), non_strict.items.len);
}

test "toon malformed headers fall through only in non strict mode" {
    const value = try serde.toon.parse(testing.allocator,
        \\foo[1][bar]: 10
        \\foo[2]extra: a,b
    , .{ .strict = false });
    defer value.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 2), value.object.len);
    try testing.expectEqualStrings("foo[1][bar]", value.object[0].key);
    try testing.expectEqual(serde.toon.Value{ .uint = 10 }, value.object[0].value);
    try testing.expectEqualStrings("foo[2]extra", value.object[1].key);
    try testing.expectEqualStrings("a,b", value.object[1].value.string);

    try testing.expectError(error.InvalidHeader, serde.toon.validate(testing.allocator, "foo[1][bar]: 10", .{}));
    try testing.expectError(error.InvalidHeader, serde.toon.validate(testing.allocator, "foo[2]extra: a,b", .{}));
}

test "toon strict rejects malformed array headers" {
    const cases = [_][]const u8{
        "foo[1] : a",
        "foo[1]extra: a",
        "foo[x]: a",
        "foo[-1]: a",
        "foo[01]: a",
    };
    for (cases) |case| {
        try testing.expectError(error.InvalidHeader, serde.toon.validate(testing.allocator, case, .{}));
    }
}

test "toon strict rejects delimiter mismatch in tabular header fields" {
    try testing.expectError(error.InvalidHeader, serde.toon.validate(testing.allocator,
        \\rows[1|]{a,b}:
        \\  1|2
    , .{}));
}

test "toon root arrays reject trailing non blank lines" {
    try testing.expectError(error.InvalidSyntax, serde.toon.validate(testing.allocator,
        \\[1]: a
        \\extra: b
    , .{}));
}

test "toon list item arrays encode canonical headers" {
    const Child = struct { id: u32, name: []const u8 };
    const Empty = struct {};
    const PrimitiveItem = struct { tags: []const []const u8, name: []const u8 };
    const TabularItem = struct { kids: []const Child, name: []const u8 };
    const EmptyArrayItem = struct { tags: []const []const u8, name: []const u8 };
    const EmptyObjectsItem = struct { kids: []const Empty, name: []const u8 };

    const primitive_tags: []const []const u8 = &.{ "a", "b" };
    const primitive_items: []const PrimitiveItem = &.{.{ .tags = primitive_tags, .name = "one" }};
    const primitive = try serde.toon.toSlice(testing.allocator, .{ .items = primitive_items });
    defer testing.allocator.free(primitive);
    try testing.expectEqualStrings(
        \\items[1]:
        \\  - tags[2]: a,b
        \\    name: one
    , primitive);

    const kids: []const Child = &.{ .{ .id = 1, .name = "Ada" }, .{ .id = 2, .name = "Bob" } };
    const tabular_items: []const TabularItem = &.{.{ .kids = kids, .name = "team" }};
    const tabular = try serde.toon.toSlice(testing.allocator, .{ .items = tabular_items });
    defer testing.allocator.free(tabular);
    try testing.expectEqualStrings(
        \\items[1]:
        \\  - kids[2]{id,name}:
        \\      1,Ada
        \\      2,Bob
        \\    name: team
    , tabular);

    const empty_tags: []const []const u8 = &.{};
    const empty_array_items: []const EmptyArrayItem = &.{.{ .tags = empty_tags, .name = "none" }};
    const empty_array = try serde.toon.toSlice(testing.allocator, .{ .items = empty_array_items });
    defer testing.allocator.free(empty_array);
    try testing.expectEqualStrings(
        \\items[1]:
        \\  - tags: []
        \\    name: none
    , empty_array);

    const empty_kids: []const Empty = &.{ .{}, .{} };
    const empty_object_items: []const EmptyObjectsItem = &.{.{ .kids = empty_kids, .name = "empty" }};
    const empty_objects = try serde.toon.toSlice(testing.allocator, .{ .items = empty_object_items });
    defer testing.allocator.free(empty_objects);
    try testing.expectEqualStrings(
        \\items[1]:
        \\  - kids[2]:
        \\      -
        \\      -
        \\    name: empty
    , empty_objects);
}

test "toon path expansion conflicts and last write wins" {
    try testing.expectError(error.ExpansionConflict, serde.toon.validate(testing.allocator,
        \\a: 1
        \\a.b: 2
    , .{ .expand_paths = .safe }));

    const overwritten = try serde.toon.parse(testing.allocator,
        \\a.b: 1
        \\a: 2
    , .{ .strict = false, .expand_paths = .safe });
    defer overwritten.deinit(testing.allocator);
    try testing.expectEqual(serde.toon.Value{ .uint = 2 }, overwritten.object[0].value);

    const expanded = try serde.toon.parse(testing.allocator,
        \\a: 2
        \\a.b: 1
    , .{ .strict = false, .expand_paths = .safe });
    defer expanded.deinit(testing.allocator);
    try testing.expectEqualStrings("a", expanded.object[0].key);
    try testing.expectEqualStrings("b", expanded.object[0].value.object[0].key);
    try testing.expectEqual(serde.toon.Value{ .uint = 1 }, expanded.object[0].value.object[0].value);
}

test "toon number and string edge cases" {
    const Numbers = struct {
        small: f64,
        big: f64,
        neg_zero: f64,
        quoted: []const u8,
    };
    const bytes = try serde.toon.toSlice(testing.allocator, Numbers{
        .small = 0.000001,
        .big = 1e20,
        .neg_zero = -0.0,
        .quoted = "true",
    });
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\small: 0.000001
        \\big: 100000000000000000000
        \\neg_zero: 0
        \\quoted: "true"
    , bytes);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const ambiguous = try serde.toon.fromSlice([]const u8, arena.allocator(), "\"001\"");
    try testing.expectEqualStrings("001", ambiguous);
}
