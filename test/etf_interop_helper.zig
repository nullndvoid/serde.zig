const std = @import("std");
const serde = @import("serde");
const compat = @import("compat");

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    const otp_path = args.next() orelse return error.MissingOtpCorpus;
    const zig_path = args.next() orelse return error.MissingZigCorpus;
    if (args.next() != null) return error.TooManyArguments;

    const input = try compat.readFileAlloc(init.gpa, otp_path, 10 * 1024 * 1024);
    defer init.gpa.free(input);
    try decodeCorpus(init.gpa, input);

    var output: compat.Io.Writer.Allocating = .init(init.gpa);
    defer output.deinit();
    try appendTyped(init.gpa, &output.writer, true);
    try appendTerm(init.gpa, &output.writer, .{ .atom = @constCast("null") });
    try appendTyped(init.gpa, &output.writer, @as([]const u8, "zig"));
    try appendTyped(init.gpa, &output.writer, @as(i64, -2147483649));
    try appendTyped(init.gpa, &output.writer, @as(u128, 1) << 100);
    try appendTyped(init.gpa, &output.writer, .{ @as([]const u8, "tuple"), @as(u8, 42) });
    try appendTyped(init.gpa, &output.writer, struct { name: []const u8, age: u8 }{ .name = "Ada", .age = 37 });

    var tail = serde.etf.Term{ .atom = @constCast("tail") };
    var elements = [_]serde.etf.Term{ .{ .integer = 1 }, .{ .integer = 2 } };
    try appendTerm(init.gpa, &output.writer, .{ .list = .{ .elements = &elements, .tail = &tail } });

    try compat.writeFile(zig_path, output.writer.buffer[0..output.writer.end]);
}

fn decodeCorpus(allocator: std.mem.Allocator, input: []const u8) !void {
    var pos: usize = 0;
    var count: usize = 0;
    while (pos < input.len) {
        if (input.len - pos < 4) return error.TruncatedCorpus;
        const len: usize = std.mem.readInt(u32, input[pos..][0..4], .big);
        pos += 4;
        if (len > input.len - pos) return error.TruncatedCorpus;
        var term = try serde.etf.decodeTerm(allocator, input[pos..][0..len], .{});
        term.deinit(allocator);
        pos += len;
        count += 1;
    }
    if (count == 0) return error.EmptyCorpus;
}

fn appendTyped(allocator: std.mem.Allocator, writer: *compat.Io.Writer, value: anytype) !void {
    const encoded = try serde.etf.toSlice(allocator, value);
    defer allocator.free(encoded);
    try appendBytes(writer, encoded);
}

fn appendTerm(allocator: std.mem.Allocator, writer: *compat.Io.Writer, term: serde.etf.Term) !void {
    const encoded = try serde.etf.encodeTerm(allocator, term, .{});
    defer allocator.free(encoded);
    try appendBytes(writer, encoded);
}

fn appendBytes(writer: *compat.Io.Writer, bytes: []const u8) !void {
    if (bytes.len > std.math.maxInt(u32)) return error.TermTooLarge;
    var size: [4]u8 = undefined;
    std.mem.writeInt(u32, &size, @intCast(bytes.len), .big);
    try writer.writeAll(&size);
    try writer.writeAll(bytes);
}
