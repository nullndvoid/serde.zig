const std = @import("std");

pub const BigInteger = struct {
    negative: bool,
    /// Base-256 magnitude, least-significant byte first. Zero is an empty slice.
    magnitude: []u8,
};

pub const Pid = struct {
    node: []u8,
    id: u32,
    serial: u32,
    creation: u32,
};

pub const Port = struct {
    node: []u8,
    id: u64,
    creation: u32,
};

pub const Reference = struct {
    node: []u8,
    creation: u32,
    ids: []u32,
};

pub const BitBinary = struct {
    bytes: []u8,
    /// Significant bits in the last byte, in the range 1...8.
    bits: u4,
};

pub const List = struct {
    elements: []Term,
    /// Null denotes NIL_EXT (a proper list). Otherwise this is the improper tail.
    tail: ?*Term = null,
};

pub const MapEntry = struct {
    key: Term,
    value: Term,
};

pub const NewFun = struct {
    arity: u8,
    uniq: [16]u8,
    index: u32,
    module: []u8,
    old_index: i32,
    old_uniq: i32,
    pid: Pid,
    free_vars: []Term,
};

pub const LegacyFun = struct {
    pid: Pid,
    module: []u8,
    index: i32,
    uniq: i32,
    free_vars: []Term,
};

pub const Export = struct {
    module: []u8,
    function: []u8,
    arity: u8,
};

pub const Record = struct {
    exported: bool,
    module: []u8,
    name: []u8,
    field_names: [][]u8,
    values: []Term,
};

/// An owning, exact semantic representation of an Erlang term.
///
/// All slices are owned by the allocator passed to the decoder/clone operation.
/// `local` contains the opaque bytes after LOCAL_EXT and is only meaningful at
/// the top level.
pub const Term = union(enum) {
    integer: i64,
    big_integer: BigInteger,
    float: f64,
    atom: []u8,
    pid: Pid,
    port: Port,
    reference: Reference,
    tuple: []Term,
    map: []MapEntry,
    nil,
    list: List,
    binary: []u8,
    bit_binary: BitBinary,
    new_fun: NewFun,
    legacy_fun: LegacyFun,
    @"export": Export,
    record: Record,
    local: []u8,

    pub fn deinit(self: *Term, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .integer, .float, .nil => {},
            .big_integer => |v| allocator.free(v.magnitude),
            .atom, .binary, .local => |v| allocator.free(v),
            .pid => |v| allocator.free(v.node),
            .port => |v| allocator.free(v.node),
            .reference => |v| {
                allocator.free(v.node);
                allocator.free(v.ids);
            },
            .tuple => |items| deinitTerms(items, allocator),
            .map => |entries| {
                for (entries) |*entry| {
                    entry.key.deinit(allocator);
                    entry.value.deinit(allocator);
                }
                allocator.free(entries);
            },
            .list => |v| {
                deinitTerms(v.elements, allocator);
                if (v.tail) |tail| {
                    tail.deinit(allocator);
                    allocator.destroy(tail);
                }
            },
            .bit_binary => |v| allocator.free(v.bytes),
            .new_fun => |v| {
                allocator.free(v.module);
                allocator.free(v.pid.node);
                deinitTerms(v.free_vars, allocator);
            },
            .legacy_fun => |v| {
                allocator.free(v.module);
                allocator.free(v.pid.node);
                deinitTerms(v.free_vars, allocator);
            },
            .@"export" => |v| {
                allocator.free(v.module);
                allocator.free(v.function);
            },
            .record => |v| {
                allocator.free(v.module);
                allocator.free(v.name);
                for (v.field_names) |name| allocator.free(name);
                allocator.free(v.field_names);
                deinitTerms(v.values, allocator);
            },
        }
        self.* = .nil;
    }

    pub fn clone(self: Term, allocator: std.mem.Allocator) error{OutOfMemory}!Term {
        return switch (self) {
            .integer => |v| .{ .integer = v },
            .float => |v| .{ .float = v },
            .nil => .nil,
            .big_integer => |v| .{ .big_integer = .{
                .negative = v.negative,
                .magnitude = try allocator.dupe(u8, v.magnitude),
            } },
            .atom => |v| .{ .atom = try allocator.dupe(u8, v) },
            .binary => |v| .{ .binary = try allocator.dupe(u8, v) },
            .local => |v| .{ .local = try allocator.dupe(u8, v) },
            .pid => |v| .{ .pid = try clonePid(v, allocator) },
            .port => |v| .{ .port = .{
                .node = try allocator.dupe(u8, v.node),
                .id = v.id,
                .creation = v.creation,
            } },
            .reference => |v| blk: {
                const node = try allocator.dupe(u8, v.node);
                errdefer allocator.free(node);
                break :blk .{ .reference = .{
                    .node = node,
                    .creation = v.creation,
                    .ids = try allocator.dupe(u32, v.ids),
                } };
            },
            .tuple => |v| .{ .tuple = try cloneTerms(v, allocator) },
            .map => |v| .{ .map = try cloneEntries(v, allocator) },
            .list => |v| blk: {
                const elements = try cloneTerms(v.elements, allocator);
                errdefer deinitTerms(elements, allocator);
                var tail_copy: ?*Term = null;
                if (v.tail) |tail| {
                    const ptr = try allocator.create(Term);
                    errdefer allocator.destroy(ptr);
                    ptr.* = try tail.clone(allocator);
                    tail_copy = ptr;
                }
                break :blk .{ .list = .{ .elements = elements, .tail = tail_copy } };
            },
            .bit_binary => |v| .{ .bit_binary = .{
                .bytes = try allocator.dupe(u8, v.bytes),
                .bits = v.bits,
            } },
            .new_fun => |v| blk: {
                const module = try allocator.dupe(u8, v.module);
                errdefer allocator.free(module);
                const pid = try clonePid(v.pid, allocator);
                errdefer allocator.free(pid.node);
                break :blk .{ .new_fun = .{
                    .arity = v.arity,
                    .uniq = v.uniq,
                    .index = v.index,
                    .module = module,
                    .old_index = v.old_index,
                    .old_uniq = v.old_uniq,
                    .pid = pid,
                    .free_vars = try cloneTerms(v.free_vars, allocator),
                } };
            },
            .legacy_fun => |v| blk: {
                const module = try allocator.dupe(u8, v.module);
                errdefer allocator.free(module);
                const pid = try clonePid(v.pid, allocator);
                errdefer allocator.free(pid.node);
                break :blk .{ .legacy_fun = .{
                    .pid = pid,
                    .module = module,
                    .index = v.index,
                    .uniq = v.uniq,
                    .free_vars = try cloneTerms(v.free_vars, allocator),
                } };
            },
            .@"export" => |v| blk: {
                const module = try allocator.dupe(u8, v.module);
                errdefer allocator.free(module);
                break :blk .{ .@"export" = .{
                    .module = module,
                    .function = try allocator.dupe(u8, v.function),
                    .arity = v.arity,
                } };
            },
            .record => |v| .{ .record = try cloneRecord(v, allocator) },
        };
    }

    /// Hash consistent with `eql`: terms that compare equal hash equally.
    /// Map entries combine commutatively, an empty proper list hashes as
    /// `nil`, and `-0.0` hashes as `0.0`.
    pub fn hash(self: Term, seed: u64) u64 {
        var hasher = std.hash.Wyhash.init(seed);
        self.hashInto(&hasher, seed);
        return hasher.final();
    }

    fn hashInto(self: Term, hasher: *std.hash.Wyhash, seed: u64) void {
        if (self == .list and self.list.elements.len == 0 and self.list.tail == null) {
            hashTag(hasher, .nil);
            return;
        }
        hashTag(hasher, std.meta.activeTag(self));
        switch (self) {
            .nil => {},
            .integer => |v| hashInt(hasher, @as(u64, @bitCast(v))),
            .float => |v| {
                const normalized: f64 = if (v == 0) 0 else v;
                hashInt(hasher, @as(u64, @bitCast(normalized)));
            },
            .big_integer => |v| {
                hasher.update(&.{@intFromBool(v.negative)});
                hashBytes(hasher, v.magnitude);
            },
            .atom, .binary, .local => |v| hashBytes(hasher, v),
            .pid => |v| hashPid(hasher, v),
            .port => |v| {
                hashBytes(hasher, v.node);
                hashInt(hasher, v.id);
                hashInt(hasher, v.creation);
            },
            .reference => |v| {
                hashBytes(hasher, v.node);
                hashInt(hasher, v.creation);
                hashInt(hasher, v.ids.len);
                for (v.ids) |id| hashInt(hasher, id);
            },
            .tuple => |items| {
                hashInt(hasher, items.len);
                for (items) |item| item.hashInto(hasher, seed);
            },
            .map => |entries| {
                hashInt(hasher, entries.len);
                var total: u64 = 0;
                for (entries) |entry| {
                    var entry_hasher = std.hash.Wyhash.init(seed);
                    entry.key.hashInto(&entry_hasher, seed);
                    entry.value.hashInto(&entry_hasher, seed);
                    total +%= entry_hasher.final();
                }
                hashInt(hasher, total);
            },
            .list => |v| {
                hashInt(hasher, v.elements.len);
                for (v.elements) |item| item.hashInto(hasher, seed);
                if (v.tail) |tail| {
                    hasher.update(&.{1});
                    tail.hashInto(hasher, seed);
                } else hasher.update(&.{0});
            },
            .bit_binary => |v| {
                hasher.update(&.{v.bits});
                hashBytes(hasher, v.bytes);
            },
            .new_fun => |v| {
                hasher.update(&.{v.arity});
                hasher.update(&v.uniq);
                hashInt(hasher, v.index);
                hashBytes(hasher, v.module);
                hashInt(hasher, @as(u32, @bitCast(v.old_index)));
                hashInt(hasher, @as(u32, @bitCast(v.old_uniq)));
                hashPid(hasher, v.pid);
                hashInt(hasher, v.free_vars.len);
                for (v.free_vars) |item| item.hashInto(hasher, seed);
            },
            .legacy_fun => |v| {
                hashPid(hasher, v.pid);
                hashBytes(hasher, v.module);
                hashInt(hasher, @as(u32, @bitCast(v.index)));
                hashInt(hasher, @as(u32, @bitCast(v.uniq)));
                hashInt(hasher, v.free_vars.len);
                for (v.free_vars) |item| item.hashInto(hasher, seed);
            },
            .@"export" => |v| {
                hashBytes(hasher, v.module);
                hashBytes(hasher, v.function);
                hasher.update(&.{v.arity});
            },
            .record => |v| {
                hasher.update(&.{@intFromBool(v.exported)});
                hashBytes(hasher, v.module);
                hashBytes(hasher, v.name);
                hashInt(hasher, v.field_names.len);
                for (v.field_names) |name| hashBytes(hasher, name);
                for (v.values) |item| item.hashInto(hasher, seed);
            },
        }
    }

    /// Semantic equality. Map entry order and legacy compact wire tags do not
    /// affect the result.
    pub fn eql(a: Term, b: Term) bool {
        if (std.meta.activeTag(a) != std.meta.activeTag(b)) {
            if (a == .nil and b == .list) return b.list.elements.len == 0 and b.list.tail == null;
            if (b == .nil and a == .list) return a.list.elements.len == 0 and a.list.tail == null;
            return false;
        }
        return switch (a) {
            .integer => |v| v == b.integer,
            .big_integer => |v| v.negative == b.big_integer.negative and std.mem.eql(u8, v.magnitude, b.big_integer.magnitude),
            .float => |v| v == b.float,
            .atom => |v| std.mem.eql(u8, v, b.atom),
            .pid => |v| eqlPid(v, b.pid),
            .port => |v| v.id == b.port.id and v.creation == b.port.creation and std.mem.eql(u8, v.node, b.port.node),
            .reference => |v| v.creation == b.reference.creation and std.mem.eql(u8, v.node, b.reference.node) and std.mem.eql(u32, v.ids, b.reference.ids),
            .tuple => |v| eqlTerms(v, b.tuple),
            .map => |v| eqlMap(v, b.map),
            .nil => true,
            .list => |v| eqlList(v, b.list),
            .binary => |v| std.mem.eql(u8, v, b.binary),
            .bit_binary => |v| v.bits == b.bit_binary.bits and std.mem.eql(u8, v.bytes, b.bit_binary.bytes),
            .new_fun => |v| eqlNewFun(v, b.new_fun),
            .legacy_fun => |v| eqlLegacyFun(v, b.legacy_fun),
            .@"export" => |v| v.arity == b.@"export".arity and std.mem.eql(u8, v.module, b.@"export".module) and std.mem.eql(u8, v.function, b.@"export".function),
            .record => |v| eqlRecord(v, b.record),
            .local => |v| std.mem.eql(u8, v, b.local),
        };
    }
};

fn deinitTerms(items: []Term, allocator: std.mem.Allocator) void {
    for (items) |*item| item.deinit(allocator);
    allocator.free(items);
}

fn hashTag(hasher: *std.hash.Wyhash, term: std.meta.Tag(Term)) void {
    hasher.update(&.{@intFromEnum(term)});
}

fn hashInt(hasher: *std.hash.Wyhash, value: u64) void {
    hasher.update(std.mem.asBytes(&value));
}

fn hashBytes(hasher: *std.hash.Wyhash, bytes: []const u8) void {
    hashInt(hasher, bytes.len);
    hasher.update(bytes);
}

fn hashPid(hasher: *std.hash.Wyhash, pid: Pid) void {
    hashBytes(hasher, pid.node);
    hashInt(hasher, pid.id);
    hashInt(hasher, pid.serial);
    hashInt(hasher, pid.creation);
}

fn clonePid(v: Pid, allocator: std.mem.Allocator) !Pid {
    return .{ .node = try allocator.dupe(u8, v.node), .id = v.id, .serial = v.serial, .creation = v.creation };
}

fn cloneTerms(items: []const Term, allocator: std.mem.Allocator) ![]Term {
    const out = try allocator.alloc(Term, items.len);
    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |*item| item.deinit(allocator);
        allocator.free(out);
    }
    for (items, 0..) |item, i| {
        out[i] = try item.clone(allocator);
        initialized += 1;
    }
    return out;
}

fn cloneEntries(entries: []const MapEntry, allocator: std.mem.Allocator) ![]MapEntry {
    const out = try allocator.alloc(MapEntry, entries.len);
    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |*entry| {
            entry.key.deinit(allocator);
            entry.value.deinit(allocator);
        }
        allocator.free(out);
    }
    for (entries, 0..) |entry, i| {
        out[i].key = try entry.key.clone(allocator);
        errdefer out[i].key.deinit(allocator);
        out[i].value = try entry.value.clone(allocator);
        initialized += 1;
    }
    return out;
}

fn cloneRecord(v: Record, allocator: std.mem.Allocator) !Record {
    const module = try allocator.dupe(u8, v.module);
    errdefer allocator.free(module);
    const name = try allocator.dupe(u8, v.name);
    errdefer allocator.free(name);
    const names = try allocator.alloc([]u8, v.field_names.len);
    var initialized: usize = 0;
    errdefer {
        for (names[0..initialized]) |field_name| allocator.free(field_name);
        allocator.free(names);
    }
    for (v.field_names, 0..) |field_name, i| {
        names[i] = try allocator.dupe(u8, field_name);
        initialized += 1;
    }
    const values = try cloneTerms(v.values, allocator);
    return .{ .exported = v.exported, .module = module, .name = name, .field_names = names, .values = values };
}

fn eqlPid(a: Pid, b: Pid) bool {
    return a.id == b.id and a.serial == b.serial and a.creation == b.creation and std.mem.eql(u8, a.node, b.node);
}

fn eqlTerms(a: []const Term, b: []const Term) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!x.eql(y)) return false;
    return true;
}

fn eqlMap(a: []const MapEntry, b: []const MapEntry) bool {
    if (a.len != b.len) return false;
    for (a) |left| {
        var found = false;
        for (b) |right| {
            if (left.key.eql(right.key) and left.value.eql(right.value)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn eqlList(a: List, b: List) bool {
    if (!eqlTerms(a.elements, b.elements)) return false;
    if (a.tail == null or b.tail == null) return a.tail == null and b.tail == null;
    return a.tail.?.eql(b.tail.?.*);
}

fn eqlNewFun(a: NewFun, b: NewFun) bool {
    return a.arity == b.arity and std.mem.eql(u8, &a.uniq, &b.uniq) and a.index == b.index and
        std.mem.eql(u8, a.module, b.module) and a.old_index == b.old_index and a.old_uniq == b.old_uniq and
        eqlPid(a.pid, b.pid) and eqlTerms(a.free_vars, b.free_vars);
}

fn eqlLegacyFun(a: LegacyFun, b: LegacyFun) bool {
    return eqlPid(a.pid, b.pid) and std.mem.eql(u8, a.module, b.module) and a.index == b.index and
        a.uniq == b.uniq and eqlTerms(a.free_vars, b.free_vars);
}

fn eqlRecord(a: Record, b: Record) bool {
    if (a.exported != b.exported or !std.mem.eql(u8, a.module, b.module) or !std.mem.eql(u8, a.name, b.name) or
        a.field_names.len != b.field_names.len or !eqlTerms(a.values, b.values)) return false;
    for (a.field_names, b.field_names) |x, y| if (!std.mem.eql(u8, x, y)) return false;
    return true;
}

test "Term hash agrees with eql" {
    const seed: u64 = 0x9e3779b97f4a7c15;

    var left_entries = [_]MapEntry{
        .{ .key = .{ .atom = @constCast("a") }, .value = .{ .integer = 1 } },
        .{ .key = .{ .integer = 2 }, .value = .{ .binary = @constCast("b") } },
    };
    var right_entries = [_]MapEntry{ left_entries[1], left_entries[0] };
    const left = Term{ .map = &left_entries };
    const right = Term{ .map = &right_entries };
    try std.testing.expect(left.eql(right));
    try std.testing.expectEqual(left.hash(seed), right.hash(seed));

    const empty_list = Term{ .list = .{ .elements = &.{} } };
    try std.testing.expect(empty_list.eql(.nil));
    try std.testing.expectEqual(empty_list.hash(seed), (@as(Term, .nil)).hash(seed));

    const positive_zero = Term{ .float = 0.0 };
    const negative_zero = Term{ .float = -0.0 };
    try std.testing.expect(positive_zero.eql(negative_zero));
    try std.testing.expectEqual(positive_zero.hash(seed), negative_zero.hash(seed));

    const integer_one = Term{ .integer = 1 };
    const float_one = Term{ .float = 1.0 };
    try std.testing.expect(!integer_one.eql(float_one));
    try std.testing.expect(integer_one.hash(seed) != float_one.hash(seed));
}

test "Term clone and semantic map equality" {
    const allocator = std.testing.allocator;
    var left = Term{ .map = try allocator.alloc(MapEntry, 2) };
    left.map[0] = .{ .key = .{ .atom = try allocator.dupe(u8, "a") }, .value = .{ .integer = 1 } };
    left.map[1] = .{ .key = .{ .integer = 2 }, .value = .{ .binary = try allocator.dupe(u8, "b") } };
    defer left.deinit(allocator);

    var right = try left.clone(allocator);
    defer right.deinit(allocator);
    std.mem.swap(MapEntry, &right.map[0], &right.map[1]);
    try std.testing.expect(left.eql(right));
}
