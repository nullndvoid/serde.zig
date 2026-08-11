const std = @import("std");
const compat = @import("compat");
const core_serialize = @import("../../core/serialize.zig");
const codec = @import("codec.zig");

const Allocator = std.mem.Allocator;

pub const SerializeError = codec.EncodeError;

/// Serde visitor that writes canonical, version-free ETF terms.
pub const Serializer = struct {
    out: *compat.Io.Writer,
    allocator: Allocator,
    options: codec.EncodeOptions,
    depth: usize = 0,

    pub const Error = SerializeError;

    pub fn init(out: *compat.Io.Writer, allocator: Allocator, options: codec.EncodeOptions) Serializer {
        var body_options = options;
        body_options.compression = .never;
        return .{ .out = out, .allocator = allocator, .options = body_options };
    }

    pub fn serializeBool(self: *Serializer, value: bool) Error!void {
        try self.write(.{ .atom = @constCast(if (value) "true" else "false") });
    }

    pub fn serializeInt(self: *Serializer, value: anytype) Error!void {
        const T = @TypeOf(value);
        const info = @typeInfo(T);
        if (info == .comptime_int) {
            const Fitting = std.math.IntFittingRange(value, value);
            return self.serializeFixedInt(@as(Fitting, value));
        }
        return self.serializeFixedInt(value);
    }

    pub fn serializeFloat(self: *Serializer, value: anytype) Error!void {
        const out: f64 = @floatCast(value);
        try self.write(.{ .float = out });
    }

    pub fn serializeString(self: *Serializer, value: []const u8) Error!void {
        try self.write(.{ .binary = @constCast(value) });
    }

    pub fn serializeBytes(self: *Serializer, value: []const u8) Error!void {
        try self.serializeString(value);
    }

    pub fn serializeNull(self: *Serializer) Error!void {
        try self.write(.{ .atom = @constCast("null") });
    }

    pub fn serializeVoid(self: *Serializer) Error!void {
        try self.serializeNull();
    }

    pub fn beginStruct(self: *Serializer) Error!StructSerializer {
        try self.checkContainerDepth();
        return .{
            .parent_out = self.out,
            .aw = .init(self.allocator),
            .allocator = self.allocator,
            .options = self.options,
            .depth = self.depth + 1,
        };
    }

    pub fn beginArray(self: *Serializer) Error!ArraySerializer {
        try self.checkContainerDepth();
        return .{
            .parent_out = self.out,
            .aw = .init(self.allocator),
            .allocator = self.allocator,
            .options = self.options,
            .depth = self.depth + 1,
        };
    }

    fn write(self: *Serializer, term: codec.Term) Error!void {
        try codec.encodeTermBodyToWriter(self.allocator, self.out, term, self.options);
    }

    fn serializeFixedInt(self: *Serializer, value: anytype) Error!void {
        const T = @TypeOf(value);
        const info = @typeInfo(T).int;
        if (info.signedness == .signed and value >= std.math.minInt(i64) and value <= std.math.maxInt(i64))
            return self.write(.{ .integer = @intCast(value) });
        if (info.signedness == .unsigned and value <= std.math.maxInt(i64))
            return self.write(.{ .integer = @intCast(value) });

        const U = compat.intType(.unsigned, info.bits);
        const negative = info.signedness == .signed and value < 0;
        const raw: U = if (negative)
            if (value == std.math.minInt(T)) @as(U, 1) << (info.bits - 1) else @intCast(-value)
        else
            @intCast(value);
        var bytes: [(@bitSizeOf(T) + 7) / 8]u8 = undefined;
        var magnitude = raw;
        var count: usize = 0;
        while (magnitude != 0) {
            bytes[count] = @truncate(magnitude);
            count += 1;
            if (comptime info.bits <= 8) magnitude = 0 else magnitude >>= 8;
        }
        try self.write(.{ .big_integer = .{ .negative = negative, .magnitude = bytes[0..count] } });
    }

    fn checkContainerDepth(self: *Serializer) Error!void {
        if (self.depth >= self.options.max_depth) return error.DepthLimit;
    }
};

pub const StructSerializer = struct {
    parent_out: *compat.Io.Writer,
    aw: compat.Io.Writer.Allocating,
    allocator: Allocator,
    options: codec.EncodeOptions,
    depth: usize,
    count: usize = 0,
    active: bool = true,
    field_names: compat.ArrayList([]const u8) = .empty,

    pub const Error = SerializeError;

    pub fn serializeField(self: *StructSerializer, comptime key: []const u8, value: anytype) Error!void {
        try self.checkSlot();
        for (self.field_names.items) |previous| if (std.mem.eql(u8, previous, key)) return error.DuplicateMapKey;
        self.field_names.append(self.allocator, key) catch return error.OutOfMemory;
        var child = Serializer{ .out = &self.aw.writer, .allocator = self.allocator, .options = self.options, .depth = self.depth };
        try child.serializeString(key);
        try core_serialize.serialize(@TypeOf(value), value, &child, .{});
        if (self.aw.writer.end > self.options.max_size) return error.SizeLimit;
        self.count += 1;
    }

    pub fn serializeEntry(self: *StructSerializer, key: anytype, value: anytype) Error!void {
        try self.checkSlot();
        var child = Serializer{ .out = &self.aw.writer, .allocator = self.allocator, .options = self.options, .depth = self.depth };
        try core_serialize.serialize(@TypeOf(key), key, &child, .{});
        try core_serialize.serialize(@TypeOf(value), value, &child, .{});
        if (self.aw.writer.end > self.options.max_size) return error.SizeLimit;
        self.count += 1;
    }

    pub fn end(self: *StructSerializer) Error!void {
        defer self.deinit();
        if (self.count > self.options.max_collection_elements) return error.SizeLimit;
        self.parent_out.writeByte(@intFromEnum(codec.Tag.map_ext)) catch return error.WriteFailed;
        try writeLength(self.parent_out, self.count);
        self.parent_out.writeAll(self.aw.writer.buffer[0..self.aw.writer.end]) catch return error.WriteFailed;
        if (self.parent_out.end > self.options.max_size) return error.SizeLimit;
    }

    fn checkSlot(self: *StructSerializer) Error!void {
        if (self.count >= self.options.max_collection_elements) return error.SizeLimit;
    }

    pub fn deinit(self: *StructSerializer) void {
        if (!self.active) return;
        self.aw.deinit();
        self.field_names.deinit(self.allocator);
        self.active = false;
    }
};

pub const ArraySerializer = struct {
    parent_out: *compat.Io.Writer,
    aw: compat.Io.Writer.Allocating,
    allocator: Allocator,
    options: codec.EncodeOptions,
    depth: usize,
    count: usize = 0,
    active: bool = true,

    pub const Error = SerializeError;

    pub fn serializeBool(self: *ArraySerializer, value: bool) Error!void {
        try self.checkSlot();
        var child_serializer = self.childSerializer();
        try child_serializer.serializeBool(value);
        try self.checkSize();
        self.count += 1;
    }

    pub fn serializeInt(self: *ArraySerializer, value: anytype) Error!void {
        try self.checkSlot();
        var child_serializer = self.childSerializer();
        try child_serializer.serializeInt(value);
        try self.checkSize();
        self.count += 1;
    }

    pub fn serializeFloat(self: *ArraySerializer, value: anytype) Error!void {
        try self.checkSlot();
        var child_serializer = self.childSerializer();
        try child_serializer.serializeFloat(value);
        try self.checkSize();
        self.count += 1;
    }

    pub fn serializeString(self: *ArraySerializer, value: []const u8) Error!void {
        try self.checkSlot();
        var child_serializer = self.childSerializer();
        try child_serializer.serializeString(value);
        try self.checkSize();
        self.count += 1;
    }

    pub fn serializeBytes(self: *ArraySerializer, value: []const u8) Error!void {
        try self.serializeString(value);
    }

    pub fn serializeNull(self: *ArraySerializer) Error!void {
        try self.checkSlot();
        var child_serializer = self.childSerializer();
        try child_serializer.serializeNull();
        try self.checkSize();
        self.count += 1;
    }

    pub fn serializeVoid(self: *ArraySerializer) Error!void {
        try self.serializeNull();
    }

    pub fn beginStruct(self: *ArraySerializer) Error!StructSerializer {
        try self.checkSlot();
        if (self.depth >= self.options.max_depth) return error.DepthLimit;
        self.count += 1;
        return .{ .parent_out = &self.aw.writer, .aw = .init(self.allocator), .allocator = self.allocator, .options = self.options, .depth = self.depth + 1 };
    }

    pub fn beginArray(self: *ArraySerializer) Error!ArraySerializer {
        try self.checkSlot();
        if (self.depth >= self.options.max_depth) return error.DepthLimit;
        self.count += 1;
        return .{ .parent_out = &self.aw.writer, .aw = .init(self.allocator), .allocator = self.allocator, .options = self.options, .depth = self.depth + 1 };
    }

    pub fn end(self: *ArraySerializer) Error!void {
        defer self.deinit();
        if (self.count > self.options.max_collection_elements) return error.SizeLimit;
        if (self.count == 0) {
            self.parent_out.writeByte(@intFromEnum(codec.Tag.nil_ext)) catch return error.WriteFailed;
            return;
        }
        self.parent_out.writeByte(@intFromEnum(codec.Tag.list_ext)) catch return error.WriteFailed;
        try writeLength(self.parent_out, self.count);
        self.parent_out.writeAll(self.aw.writer.buffer[0..self.aw.writer.end]) catch return error.WriteFailed;
        self.parent_out.writeByte(@intFromEnum(codec.Tag.nil_ext)) catch return error.WriteFailed;
        if (self.parent_out.end > self.options.max_size) return error.SizeLimit;
    }

    fn childSerializer(self: *ArraySerializer) Serializer {
        return .{ .out = &self.aw.writer, .allocator = self.allocator, .options = self.options, .depth = self.depth };
    }

    fn checkSlot(self: *ArraySerializer) Error!void {
        if (self.count >= self.options.max_collection_elements) return error.SizeLimit;
    }

    fn checkSize(self: *ArraySerializer) Error!void {
        if (self.aw.writer.end > self.options.max_size) return error.SizeLimit;
    }

    pub fn deinit(self: *ArraySerializer) void {
        if (!self.active) return;
        self.aw.deinit();
        self.active = false;
    }
};

fn writeLength(writer: *compat.Io.Writer, len: usize) SerializeError!void {
    if (len > std.math.maxInt(u32)) return error.LengthOverflow;
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, @intCast(len), .big);
    writer.writeAll(&bytes) catch return error.WriteFailed;
}
