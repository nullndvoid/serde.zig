const std = @import("std");
const serde = @import("serde");

const FuzzTarget = struct {
    id: u128,
    name: []const u8,
    enabled: bool,
    values: []const i64,
    note: ?[]const u8 = null,
};

export fn LLVMFuzzerTestOneInput(data: [*]const u8, size: usize) callconv(.c) c_int {
    const input = data[0..size];
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    if (serde.etf.decodeTerm(allocator, input, .{})) |term_value| {
        var term = term_value;
        term.deinit(allocator);
    } else |_| {}
    _ = serde.etf.fromSlice(FuzzTarget, allocator, input) catch {};
    _ = serde.etf.fromSlice([]const u8, allocator, input) catch {};
    _ = serde.etf.fromSlice(i128, allocator, input) catch {};

    const flags = serde.etf.distribution.CapabilityFlags{
        .bits = serde.etf.distribution.CapabilityFlags.dist_hdr_atom_cache |
            serde.etf.distribution.CapabilityFlags.utf8_atoms |
            serde.etf.distribution.CapabilityFlags.fragments,
    };
    var decoder = serde.etf.distribution.Decoder.init(allocator, flags, .{});
    defer decoder.deinit();
    decoder.feed(input) catch return 0;
    while (decoder.next() catch null) |message_value| {
        var message = message_value;
        message.deinit(allocator);
    }
    return 0;
}
