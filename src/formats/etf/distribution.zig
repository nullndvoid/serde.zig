//! Stateful OTP 29 distribution framing and atom-cache codec.
//!
//! This module starts after a distribution handshake has negotiated flags.
//! It deliberately does not implement sockets, EPMD, cookies, handshakes or TLS.

const std = @import("std");
const compat = @import("compat");
const codec = @import("codec.zig");
const term_mod = @import("term.zig");

pub const Term = term_mod.Term;

pub const CapabilityFlags = struct {
    bits: u64 = 0,

    pub const published: u64 = 0x1;
    pub const atom_cache: u64 = 0x2;
    pub const extended_references: u64 = 0x4;
    pub const dist_monitor: u64 = 0x8;
    pub const fun_tags: u64 = 0x10;
    pub const dist_monitor_name: u64 = 0x20;
    pub const hidden_atom_cache: u64 = 0x40;
    pub const new_fun_tags: u64 = 0x80;
    pub const extended_pids_ports: u64 = 0x100;
    pub const export_ptr_tag: u64 = 0x200;
    pub const bit_binaries: u64 = 0x400;
    pub const new_floats: u64 = 0x800;
    pub const unicode_io: u64 = 0x1000;
    pub const dist_hdr_atom_cache: u64 = 0x2000;
    pub const small_atom_tags: u64 = 0x4000;
    pub const utf8_atoms: u64 = 0x10000;
    pub const map_tag: u64 = 0x20000;
    pub const big_creation: u64 = 0x40000;
    pub const send_sender: u64 = 0x80000;
    pub const big_seqtrace_labels: u64 = 0x100000;
    pub const exit_payload: u64 = 0x400000;
    pub const fragments: u64 = 0x800000;
    pub const handshake_23: u64 = 0x1000000;
    pub const unlink_id: u64 = 0x2000000;
    pub const spawn: u64 = @as(u64, 1) << 32;
    pub const name_me: u64 = @as(u64, 1) << 33;
    pub const v4_nc: u64 = @as(u64, 1) << 34;
    pub const alias: u64 = @as(u64, 1) << 35;
    pub const mandatory_25_digest: u64 = @as(u64, 1) << 36;
    pub const altact_sig: u64 = @as(u64, 1) << 37;
    pub const native_records: u64 = @as(u64, 1) << 38;

    pub fn has(self: CapabilityFlags, flag: u64) bool {
        return self.bits & flag == flag;
    }
};

pub const AtomCache = struct {
    entries: [2048]?[]u8 = @splat(null),

    pub fn deinit(self: *AtomCache, allocator: std.mem.Allocator) void {
        for (&self.entries) |*entry| {
            if (entry.*) |atom| allocator.free(atom);
            entry.* = null;
        }
    }

    pub fn get(self: *const AtomCache, index: usize) ?[]const u8 {
        if (index >= self.entries.len) return null;
        return self.entries[index];
    }

    pub fn find(self: *const AtomCache, atom: []const u8) ?usize {
        for (self.entries, 0..) |entry, i| {
            if (entry) |cached| if (std.mem.eql(u8, atom, cached)) return i;
        }
        return null;
    }

    pub fn put(self: *AtomCache, allocator: std.mem.Allocator, index: usize, atom: []const u8) !void {
        if (index >= self.entries.len) return error.InvalidAtomCacheRef;
        const copy = try allocator.dupe(u8, atom);
        if (self.entries[index]) |old| allocator.free(old);
        self.entries[index] = copy;
    }
};

pub const AtomCacheReference = struct {
    cache_index: u11,
    is_new: bool,
    atom: []const u8,
};

pub const DistributionHeader = union(enum) {
    normal: []const AtomCacheReference,
    fragment_start: struct { sequence_id: u64, fragment_id: u64, references: []const AtomCacheReference },
    fragment_continuation: struct { sequence_id: u64, fragment_id: u64 },
    pass_through,
};

pub const Opcode = enum(u8) {
    link = 1,
    send = 2,
    exit = 3,
    unlink = 4,
    node_link = 5,
    reg_send = 6,
    group_leader = 7,
    exit2 = 8,
    send_tt = 12,
    exit_tt = 13,
    reg_send_tt = 16,
    exit2_tt = 18,
    monitor_p = 19,
    demonitor_p = 20,
    monitor_p_exit = 21,
    send_sender = 22,
    send_sender_tt = 23,
    payload_exit = 24,
    payload_exit_tt = 25,
    payload_exit2 = 26,
    payload_exit2_tt = 27,
    payload_monitor_p_exit = 28,
    spawn_request = 29,
    spawn_request_tt = 30,
    spawn_reply = 31,
    spawn_reply_tt = 32,
    alias_send = 33,
    alias_send_tt = 34,
    unlink_id = 35,
    unlink_id_ack = 36,
    altact_sig_send = 37,
};

pub const ControlArgs = struct {
    /// Operation fields excluding the opcode. Owned terms.
    terms: []Term,
};

pub const ControlMessage = union(enum) {
    link: ControlArgs,
    send: ControlArgs,
    exit_signal: ControlArgs,
    unlink: ControlArgs,
    node_link: ControlArgs,
    reg_send: ControlArgs,
    group_leader: ControlArgs,
    exit2: ControlArgs,
    send_tt: ControlArgs,
    exit_tt: ControlArgs,
    reg_send_tt: ControlArgs,
    exit2_tt: ControlArgs,
    monitor_p: ControlArgs,
    demonitor_p: ControlArgs,
    monitor_p_exit: ControlArgs,
    send_sender: ControlArgs,
    send_sender_tt: ControlArgs,
    payload_exit: ControlArgs,
    payload_exit_tt: ControlArgs,
    payload_exit2: ControlArgs,
    payload_exit2_tt: ControlArgs,
    payload_monitor_p_exit: ControlArgs,
    spawn_request: ControlArgs,
    spawn_request_tt: ControlArgs,
    spawn_reply: ControlArgs,
    spawn_reply_tt: ControlArgs,
    alias_send: ControlArgs,
    alias_send_tt: ControlArgs,
    unlink_id: ControlArgs,
    unlink_id_ack: ControlArgs,
    altact_sig_send: ControlArgs,
    /// An unknown/gap/future control tuple, retained exactly.
    unknown: Term,

    pub fn deinit(self: *ControlMessage, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .unknown => |*term| term.deinit(allocator),
            inline else => |control_args| deinitTerms(control_args.terms, allocator),
        }
    }

    pub fn opcode(self: ControlMessage) ?Opcode {
        return switch (self) {
            .link => .link,
            .send => .send,
            .exit_signal => .exit,
            .unlink => .unlink,
            .node_link => .node_link,
            .reg_send => .reg_send,
            .group_leader => .group_leader,
            .exit2 => .exit2,
            .send_tt => .send_tt,
            .exit_tt => .exit_tt,
            .reg_send_tt => .reg_send_tt,
            .exit2_tt => .exit2_tt,
            .monitor_p => .monitor_p,
            .demonitor_p => .demonitor_p,
            .monitor_p_exit => .monitor_p_exit,
            .send_sender => .send_sender,
            .send_sender_tt => .send_sender_tt,
            .payload_exit => .payload_exit,
            .payload_exit_tt => .payload_exit_tt,
            .payload_exit2 => .payload_exit2,
            .payload_exit2_tt => .payload_exit2_tt,
            .payload_monitor_p_exit => .payload_monitor_p_exit,
            .spawn_request => .spawn_request,
            .spawn_request_tt => .spawn_request_tt,
            .spawn_reply => .spawn_reply,
            .spawn_reply_tt => .spawn_reply_tt,
            .alias_send => .alias_send,
            .alias_send_tt => .alias_send_tt,
            .unlink_id => .unlink_id,
            .unlink_id_ack => .unlink_id_ack,
            .altact_sig_send => .altact_sig_send,
            .unknown => null,
        };
    }

    pub fn args(self: ControlMessage) ?[]const Term {
        return switch (self) {
            .unknown => null,
            inline else => |value| value.terms,
        };
    }

    pub fn fromTerm(allocator: std.mem.Allocator, input: Term) !ControlMessage {
        var term = input;
        errdefer term.deinit(allocator);
        if (term != .tuple or term.tuple.len == 0 or term.tuple[0] != .integer) return .{ .unknown = term };
        const opcode_int = term.tuple[0].integer;
        if (opcode_int < 0 or opcode_int > 255) return .{ .unknown = term };
        const opcode_value = compat.intToEnum(Opcode, @as(u8, @intCast(opcode_int))) orelse return .{ .unknown = term };
        const arg_count = term.tuple.len - 1;
        if (!validArity(opcode_value, arg_count, term.tuple[1..])) return .{ .unknown = term };

        const args_copy = allocator.alloc(Term, arg_count) catch return error.OutOfMemory;
        @memcpy(args_copy, term.tuple[1..]);
        allocator.free(term.tuple);
        const value = ControlArgs{ .terms = args_copy };
        return switch (opcode_value) {
            .link => .{ .link = value },
            .send => .{ .send = value },
            .exit => .{ .exit_signal = value },
            .unlink => .{ .unlink = value },
            .node_link => .{ .node_link = value },
            .reg_send => .{ .reg_send = value },
            .group_leader => .{ .group_leader = value },
            .exit2 => .{ .exit2 = value },
            .send_tt => .{ .send_tt = value },
            .exit_tt => .{ .exit_tt = value },
            .reg_send_tt => .{ .reg_send_tt = value },
            .exit2_tt => .{ .exit2_tt = value },
            .monitor_p => .{ .monitor_p = value },
            .demonitor_p => .{ .demonitor_p = value },
            .monitor_p_exit => .{ .monitor_p_exit = value },
            .send_sender => .{ .send_sender = value },
            .send_sender_tt => .{ .send_sender_tt = value },
            .payload_exit => .{ .payload_exit = value },
            .payload_exit_tt => .{ .payload_exit_tt = value },
            .payload_exit2 => .{ .payload_exit2 = value },
            .payload_exit2_tt => .{ .payload_exit2_tt = value },
            .payload_monitor_p_exit => .{ .payload_monitor_p_exit = value },
            .spawn_request => .{ .spawn_request = value },
            .spawn_request_tt => .{ .spawn_request_tt = value },
            .spawn_reply => .{ .spawn_reply = value },
            .spawn_reply_tt => .{ .spawn_reply_tt = value },
            .alias_send => .{ .alias_send = value },
            .alias_send_tt => .{ .alias_send_tt = value },
            .unlink_id => .{ .unlink_id = value },
            .unlink_id_ack => .{ .unlink_id_ack = value },
            .altact_sig_send => .{ .altact_sig_send = value },
        };
    }
};

pub const Message = union(enum) {
    tick,
    data: struct {
        control: ControlMessage,
        payload: ?Term = null,
    },

    pub fn deinit(self: *Message, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .tick => {},
            .data => |*data| {
                data.control.deinit(allocator);
                if (data.payload) |*payload| payload.deinit(allocator);
            },
        }
    }
};

pub const EncoderOptions = struct {
    max_frame_size: usize = 10 * 1024 * 1024,
    /// If non-null, payloads exceeding this frame size are fragmented.
    fragment_size: ?usize = null,
    term_options: codec.EncodeOptions = .{},
};

pub const EncodedFrames = struct {
    items: [][]u8,

    pub fn deinit(self: *EncodedFrames, allocator: std.mem.Allocator) void {
        for (self.items) |frame| allocator.free(frame);
        allocator.free(self.items);
        self.items = &.{};
    }
};

pub const Encoder = struct {
    allocator: std.mem.Allocator,
    flags: CapabilityFlags,
    options: EncoderOptions,
    cache: AtomCache = .{},
    next_slot: u11 = 0,
    next_sequence_id: u64 = 1,

    pub fn init(allocator: std.mem.Allocator, flags: CapabilityFlags, options: EncoderOptions) Encoder {
        return .{ .allocator = allocator, .flags = flags, .options = options };
    }

    pub fn deinit(self: *Encoder) void {
        self.cache.deinit(self.allocator);
    }

    pub fn encodeTick(self: *Encoder) ![]u8 {
        const frame = try self.allocator.alloc(u8, 4);
        @memset(frame, 0);
        return frame;
    }

    pub fn encode(self: *Encoder, control: ControlMessage, payload: ?Term) !EncodedFrames {
        if (!self.flags.has(CapabilityFlags.dist_hdr_atom_cache) or !self.flags.has(CapabilityFlags.utf8_atoms))
            return error.MissingCapability;
        try self.checkCapabilities(control, payload);
        var atom_list: compat.ArrayList([]const u8) = .empty;
        defer atom_list.deinit(self.allocator);
        if (control.args()) |args| for (args) |term| try collectAtoms(self.allocator, &atom_list, term);
        if (control == .unknown) try collectAtoms(self.allocator, &atom_list, control.unknown);
        if (payload) |term| try collectAtoms(self.allocator, &atom_list, term);
        if (atom_list.items.len > 255) atom_list.shrinkRetainingCapacity(255);

        const saved_next_slot = self.next_slot;
        errdefer self.next_slot = saved_next_slot;
        var references_committed = false;
        const refs = try self.buildReferences(atom_list.items);
        defer self.allocator.free(refs);
        defer if (!references_committed) {
            freeStagedReferences(self.allocator, refs);
            self.next_slot = saved_next_slot;
        };
        const atom_refs = try self.allocator.alloc([]const u8, refs.len);
        defer self.allocator.free(atom_refs);
        for (refs, 0..) |ref, i| atom_refs[i] = ref.atom;

        var term_options = self.options.term_options;
        term_options.compression = .never;
        term_options.atom_cache = atom_refs;
        var control_term = try controlAsTerm(self.allocator, control);
        defer if (control == .unknown) control_term.deinit(self.allocator) else self.allocator.free(control_term.tuple);
        var control_writer: compat.Io.Writer.Allocating = .init(self.allocator);
        defer control_writer.deinit();
        try codec.encodeTermBodyToWriter(self.allocator, &control_writer.writer, control_term, term_options);
        const control_bytes = control_writer.writer.buffer[0..control_writer.writer.end];

        var payload_writer: compat.Io.Writer.Allocating = .init(self.allocator);
        defer payload_writer.deinit();
        if (payload) |term| try codec.encodeTermBodyToWriter(self.allocator, &payload_writer.writer, term, term_options);
        const payload_bytes = payload_writer.writer.buffer[0..payload_writer.writer.end];

        var normal_header: compat.Io.Writer.Allocating = .init(self.allocator);
        defer normal_header.deinit();
        try writeHeader(&normal_header.writer, .normal, 0, 0, refs);
        const header_and_control = std.math.add(usize, normal_header.writer.end, control_bytes.len) catch return error.FrameTooLarge;
        const normal_size = std.math.add(usize, header_and_control, payload_bytes.len) catch return error.FrameTooLarge;
        const fragment_size = self.options.fragment_size;
        var result: EncodedFrames = undefined;
        if (fragment_size == null or normal_size <= fragment_size.?) {
            const frames = try self.allocator.alloc([]u8, 1);
            errdefer self.allocator.free(frames);
            frames[0] = try makeFrame(self.allocator, &.{ normal_header.writer.buffer[0..normal_header.writer.end], control_bytes, payload_bytes }, self.options.max_frame_size);
            result = .{ .items = frames };
        } else {
            if (!self.flags.has(CapabilityFlags.fragments)) return error.MissingCapability;
            if (payload == null) return error.FrameTooLarge;
            result = try self.fragment(refs, control_bytes, payload_bytes, fragment_size.?);
        }
        errdefer result.deinit(self.allocator);
        self.commitReferences(refs);
        references_committed = true;
        return result;
    }

    fn fragment(self: *Encoder, refs: []const AtomCacheReference, control: []const u8, payload: []const u8, target: usize) !EncodedFrames {
        var probe: compat.Io.Writer.Allocating = .init(self.allocator);
        defer probe.deinit();
        try writeHeader(&probe.writer, .fragment_start, self.next_sequence_id, 1, refs);
        const fixed_first = std.math.add(usize, probe.writer.end, control.len) catch return error.FrameTooLarge;
        if (fixed_first >= target or target <= 18) return error.FrameTooLarge;
        const first_capacity = target - probe.writer.end - control.len;
        const continuation_capacity = target - 18;
        const remaining_after_first = payload.len - @min(payload.len, first_capacity);
        const continuations = if (remaining_after_first == 0) 0 else blk: {
            const rounded = std.math.add(usize, remaining_after_first, continuation_capacity - 1) catch return error.FragmentLimit;
            break :blk rounded / continuation_capacity;
        };
        const total = std.math.add(usize, continuations, 1) catch return error.FragmentLimit;
        if (total > 1024 or total > std.math.maxInt(u64)) return error.FragmentLimit;

        const frames = try self.allocator.alloc([]u8, total);
        var initialized: usize = 0;
        errdefer {
            for (frames[0..initialized]) |frame| self.allocator.free(frame);
            self.allocator.free(frames);
        }
        const sequence = self.next_sequence_id;
        self.next_sequence_id +%= 1;
        if (self.next_sequence_id == 0) self.next_sequence_id = 1;
        var offset: usize = 0;
        for (0..total) |i| {
            const fragment_id: u64 = @intCast(total - i);
            var header: compat.Io.Writer.Allocating = .init(self.allocator);
            defer header.deinit();
            if (i == 0) {
                try writeHeader(&header.writer, .fragment_start, sequence, fragment_id, refs);
                const amount = @min(first_capacity, payload.len);
                frames[i] = try makeFrame(self.allocator, &.{ header.writer.buffer[0..header.writer.end], control, payload[0..amount] }, self.options.max_frame_size);
                offset = amount;
            } else {
                try writeHeader(&header.writer, .fragment_continuation, sequence, fragment_id, &.{});
                const amount = @min(continuation_capacity, payload.len - offset);
                frames[i] = try makeFrame(self.allocator, &.{ header.writer.buffer[0..header.writer.end], payload[offset..][0..amount] }, self.options.max_frame_size);
                offset += amount;
            }
            initialized += 1;
        }
        return .{ .items = frames };
    }

    fn buildReferences(self: *Encoder, atoms: []const []const u8) ![]AtomCacheReference {
        const refs = try self.allocator.alloc(AtomCacheReference, atoms.len);
        var initialized: usize = 0;
        errdefer {
            freeStagedReferences(self.allocator, refs[0..initialized]);
            self.allocator.free(refs);
        }
        for (atoms, 0..) |atom, i| {
            if (self.cache.find(atom)) |cache_index| {
                refs[i] = .{ .cache_index = @intCast(cache_index), .is_new = false, .atom = self.cache.get(cache_index).? };
            } else {
                var cache_index = self.next_slot;
                var attempts: usize = 0;
                while (referenceUsesSlot(refs[0..i], cache_index)) : (attempts += 1) {
                    if (attempts >= self.cache.entries.len) return error.InvalidAtomCacheRef;
                    cache_index +%= 1;
                }
                self.next_slot = cache_index +% 1;
                refs[i] = .{ .cache_index = cache_index, .is_new = true, .atom = try self.allocator.dupe(u8, atom) };
            }
            initialized += 1;
        }
        return refs;
    }

    fn commitReferences(self: *Encoder, refs: []const AtomCacheReference) void {
        for (refs) |ref| {
            if (!ref.is_new) continue;
            if (self.cache.entries[ref.cache_index]) |old| self.allocator.free(old);
            self.cache.entries[ref.cache_index] = @constCast(ref.atom);
        }
    }

    fn checkCapabilities(self: *Encoder, control: ControlMessage, payload: ?Term) !void {
        if (control.opcode()) |opcode| switch (opcode) {
            .spawn_request, .spawn_request_tt, .spawn_reply, .spawn_reply_tt => if (!self.flags.has(CapabilityFlags.spawn)) return error.MissingCapability,
            .send_sender, .send_sender_tt => if (!self.flags.has(CapabilityFlags.send_sender)) return error.MissingCapability,
            .payload_exit, .payload_exit_tt, .payload_exit2, .payload_exit2_tt, .payload_monitor_p_exit => if (!self.flags.has(CapabilityFlags.exit_payload)) return error.MissingCapability,
            .alias_send, .alias_send_tt => if (!self.flags.has(CapabilityFlags.alias)) return error.MissingCapability,
            .unlink_id, .unlink_id_ack => if (!self.flags.has(CapabilityFlags.unlink_id)) return error.MissingCapability,
            .altact_sig_send => if (!self.flags.has(CapabilityFlags.altact_sig)) return error.MissingCapability,
            else => {},
        };
        if (!self.flags.has(CapabilityFlags.native_records)) {
            if (payload) |term| if (containsRecord(term)) return error.MissingCapability;
            if (control.args()) |args| for (args) |term| if (containsRecord(term)) return error.MissingCapability;
            if (control == .unknown and containsRecord(control.unknown)) return error.MissingCapability;
        }
    }
};

pub const DecoderOptions = struct {
    max_frame_size: usize = 10 * 1024 * 1024,
    max_reassembled_size: usize = 10 * 1024 * 1024,
    max_buffered_size: usize = 20 * 1024 * 1024,
    max_sequences: usize = 64,
    max_fragments_per_sequence: usize = 1024,
    term_options: codec.DecodeOptions = .{},
};

const FragmentSequence = struct {
    id: u64,
    next_fragment_id: u64,
    fragment_count: usize,
    total_size: usize,
    control: ControlMessage,
    payload: compat.ArrayList(u8) = .empty,
    refs: [][]u8,

    fn deinit(self: *FragmentSequence, allocator: std.mem.Allocator) void {
        self.control.deinit(allocator);
        self.payload.deinit(allocator);
        for (self.refs) |atom| allocator.free(atom);
        allocator.free(self.refs);
    }
};

pub const Decoder = struct {
    allocator: std.mem.Allocator,
    flags: CapabilityFlags,
    options: DecoderOptions,
    cache: AtomCache = .{},
    buffer: compat.ArrayList(u8) = .empty,
    sequences: compat.ArrayList(FragmentSequence) = .empty,

    pub fn init(allocator: std.mem.Allocator, flags: CapabilityFlags, options: DecoderOptions) Decoder {
        return .{ .allocator = allocator, .flags = flags, .options = options };
    }

    pub fn deinit(self: *Decoder) void {
        self.cache.deinit(self.allocator);
        self.buffer.deinit(self.allocator);
        for (self.sequences.items) |*sequence| sequence.deinit(self.allocator);
        self.sequences.deinit(self.allocator);
    }

    pub fn feed(self: *Decoder, bytes: []const u8) !void {
        const total = std.math.add(usize, self.buffer.items.len, bytes.len) catch return error.SizeLimit;
        if (total > self.options.max_buffered_size) return error.SizeLimit;
        try self.buffer.appendSlice(self.allocator, bytes);
    }

    pub fn next(self: *Decoder) !?Message {
        while (true) {
            if (self.buffer.items.len < 4) return null;
            const frame_len: usize = std.mem.readInt(u32, self.buffer.items[0..4], .big);
            if (frame_len > self.options.max_frame_size) return error.SizeLimit;
            const total = std.math.add(usize, frame_len, 4) catch return error.SizeLimit;
            if (self.buffer.items.len < total) return null;
            if (frame_len == 0) {
                self.consume(4);
                return .tick;
            }
            const frame_copy = try self.allocator.dupe(u8, self.buffer.items[4..total]);
            defer self.allocator.free(frame_copy);
            self.consume(total);
            if (try self.decodeFrame(frame_copy)) |message| return message;
        }
    }

    fn decodeFrame(self: *Decoder, frame: []const u8) !?Message {
        if (frame.len != 0 and frame[0] == 112) return try self.decodePassThrough(frame[1..]);
        if (frame.len < 2 or frame[0] != codec.version) return error.InvalidDistributionHeader;
        return switch (frame[1]) {
            68 => try self.decodeNormal(frame[2..]),
            69 => try self.decodeFragmentStart(frame[2..]),
            70 => try self.decodeFragmentContinuation(frame[2..]),
            else => error.InvalidDistributionHeader,
        };
    }

    fn decodeNormal(self: *Decoder, bytes: []const u8) !Message {
        if (!self.flags.has(CapabilityFlags.dist_hdr_atom_cache) or !self.flags.has(CapabilityFlags.utf8_atoms))
            return error.MissingCapability;
        var parsed = try self.parseReferences(bytes);
        defer parsed.deinit(self.allocator);
        return try self.decodeTerms(bytes[parsed.consumed..], parsed.atoms);
    }

    fn decodePassThrough(self: *Decoder, bytes: []const u8) !Message {
        var cursor = bytes;
        if (cursor.len == 0 or cursor[0] != codec.version) return error.InvalidVersion;
        cursor = cursor[1..];
        var terms = codec.Decoder.initBody(self.allocator, cursor, self.options.term_options);
        const control_term = try terms.next();
        var control = try ControlMessage.fromTerm(self.allocator, control_term);
        errdefer control.deinit(self.allocator);
        cursor = cursor[terms.pos..];
        var payload: ?Term = null;
        if (cursor.len != 0) {
            if (cursor[0] != codec.version) return error.InvalidVersion;
            var payload_decoder = codec.Decoder.initBody(self.allocator, cursor[1..], self.options.term_options);
            payload = try payload_decoder.next();
            if (payload_decoder.remaining() != 0) {
                payload.?.deinit(self.allocator);
                return error.TrailingData;
            }
        }
        return .{ .data = .{ .control = control, .payload = payload } };
    }

    fn decodeFragmentStart(self: *Decoder, bytes: []const u8) !?Message {
        if (!self.flags.has(CapabilityFlags.fragments)) return error.MissingCapability;
        if (bytes.len < 16) return error.UnexpectedEof;
        const sequence_id = std.mem.readInt(u64, bytes[0..8], .big);
        const fragment_id = std.mem.readInt(u64, bytes[8..16], .big);
        if (fragment_id == 0 or fragment_id > self.options.max_fragments_per_sequence) return error.FragmentLimit;
        if (self.findSequence(sequence_id) != null) return error.DuplicateFragment;
        if (self.sequences.items.len >= self.options.max_sequences) return error.SequenceLimit;
        var parsed = try self.parseReferences(bytes[16..]);
        defer parsed.deinit(self.allocator);
        const body = bytes[16 + parsed.consumed ..];
        var term_options = self.options.term_options;
        term_options.atom_cache = parsed.atoms;
        var cursor = codec.Decoder.initBody(self.allocator, body, term_options);
        const control_term = try cursor.next();
        var control = try ControlMessage.fromTerm(self.allocator, control_term);
        errdefer control.deinit(self.allocator);

        const refs = try cloneAtomRefs(self.allocator, parsed.atoms);
        errdefer freeAtomRefs(self.allocator, refs);
        var sequence = FragmentSequence{
            .id = sequence_id,
            .next_fragment_id = fragment_id - 1,
            .fragment_count = 1,
            .total_size = body.len,
            .control = control,
            .refs = refs,
        };
        errdefer sequence.deinit(self.allocator);
        if (sequence.total_size > self.options.max_reassembled_size) return error.SizeLimit;
        try sequence.payload.appendSlice(self.allocator, body[cursor.pos..]);
        if (fragment_id == 1) {
            const message = try self.finishSequenceValue(&sequence);
            sequence.deinit(self.allocator);
            return message;
        }
        try self.sequences.append(self.allocator, sequence);
        return null;
    }

    fn decodeFragmentContinuation(self: *Decoder, bytes: []const u8) !?Message {
        if (!self.flags.has(CapabilityFlags.fragments)) return error.MissingCapability;
        if (bytes.len < 16) return error.UnexpectedEof;
        const sequence_id = std.mem.readInt(u64, bytes[0..8], .big);
        const fragment_id = std.mem.readInt(u64, bytes[8..16], .big);
        const index = self.findSequence(sequence_id) orelse return error.UnknownSequence;
        var sequence = &self.sequences.items[index];
        if (fragment_id != sequence.next_fragment_id) return error.OutOfOrderFragment;
        sequence.fragment_count = std.math.add(usize, sequence.fragment_count, 1) catch return error.FragmentLimit;
        if (sequence.fragment_count > self.options.max_fragments_per_sequence) return error.FragmentLimit;
        const new_total = std.math.add(usize, sequence.total_size, bytes.len - 16) catch return error.SizeLimit;
        if (new_total > self.options.max_reassembled_size) return error.SizeLimit;
        try sequence.payload.appendSlice(self.allocator, bytes[16..]);
        sequence.total_size = new_total;
        sequence.next_fragment_id = fragment_id - 1;
        if (fragment_id != 1) return null;

        var completed = self.sequences.swapRemove(index);
        defer completed.deinit(self.allocator);
        return try self.finishSequenceValue(&completed);
    }

    fn finishSequenceValue(self: *Decoder, sequence: *FragmentSequence) !Message {
        var options = self.options.term_options;
        const borrowed = try refsAsConst(self.allocator, sequence.refs);
        defer self.allocator.free(borrowed);
        options.atom_cache = borrowed;
        var payload_decoder = codec.Decoder.initBody(self.allocator, sequence.payload.items, options);
        var payload: ?Term = null;
        if (payload_decoder.remaining() != 0) {
            payload = try payload_decoder.next();
            if (payload_decoder.remaining() != 0) {
                payload.?.deinit(self.allocator);
                return error.TrailingData;
            }
        }
        const control = sequence.control;
        sequence.control = .{ .unknown = .nil };
        return .{ .data = .{ .control = control, .payload = payload } };
    }

    fn decodeTerms(self: *Decoder, body: []const u8, atoms: []const []const u8) !Message {
        var options = self.options.term_options;
        options.atom_cache = atoms;
        var cursor = codec.Decoder.initBody(self.allocator, body, options);
        const control_term = try cursor.next();
        var control = try ControlMessage.fromTerm(self.allocator, control_term);
        errdefer control.deinit(self.allocator);
        var payload: ?Term = null;
        if (cursor.remaining() != 0) payload = try cursor.next();
        if (cursor.remaining() != 0) {
            if (payload) |*term| term.deinit(self.allocator);
            return error.TrailingData;
        }
        return .{ .data = .{ .control = control, .payload = payload } };
    }

    const ParsedReferences = struct {
        consumed: usize,
        atoms: [][]const u8,
        fn deinit(self: *ParsedReferences, allocator: std.mem.Allocator) void {
            allocator.free(self.atoms);
        }
    };

    fn parseReferences(self: *Decoder, bytes: []const u8) !ParsedReferences {
        if (bytes.len == 0) return error.UnexpectedEof;
        const count: usize = bytes[0];
        if (count == 0) return .{ .consumed = 1, .atoms = try self.allocator.alloc([]const u8, 0) };
        const flag_count = count / 2 + 1;
        if (bytes.len < 1 + flag_count) return error.UnexpectedEof;
        const flags = bytes[1..][0..flag_count];
        const long_atoms = if (count % 2 == 0) flags[flag_count - 1] & 1 != 0 else flags[flag_count - 1] & 0x10 != 0;
        var pos: usize = 1 + flag_count;
        var cache_indices: [255]usize = undefined;
        var staged: [255]?[]u8 = @splat(null);
        defer for (staged[0..count]) |copy| if (copy) |atom| self.allocator.free(atom);
        for (0..count) |i| {
            const nibble: u8 = if (i % 2 == 0) flags[i / 2] & 0x0f else flags[i / 2] >> 4;
            const is_new = nibble & 8 != 0;
            const segment = nibble & 7;
            if (pos >= bytes.len) return error.UnexpectedEof;
            const internal = bytes[pos];
            pos += 1;
            const cache_index: usize = @as(usize, segment) * 256 + internal;
            cache_indices[i] = cache_index;
            if (is_new) {
                const atom_len: usize = if (long_atoms) blk: {
                    if (pos + 2 > bytes.len) return error.UnexpectedEof;
                    const len = std.mem.readInt(u16, bytes[pos..][0..2], .big);
                    pos += 2;
                    break :blk len;
                } else blk: {
                    if (pos >= bytes.len) return error.UnexpectedEof;
                    const len = bytes[pos];
                    pos += 1;
                    break :blk len;
                };
                if (atom_len > bytes.len - pos) return error.UnexpectedEof;
                const text = bytes[pos..][0..atom_len];
                pos += atom_len;
                if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidAtom;
                if ((std.unicode.utf8CountCodepoints(text) catch return error.InvalidAtom) > 255) return error.AtomTooLong;
                staged[i] = try self.allocator.dupe(u8, text);
            } else if (self.cache.get(cache_index) == null) return error.InvalidAtomCacheRef;
        }
        const atoms = try self.allocator.alloc([]const u8, count);
        errdefer self.allocator.free(atoms);
        for (0..count) |i| {
            if (staged[i]) |copy| {
                const cache_index = cache_indices[i];
                if (self.cache.entries[cache_index]) |old| self.allocator.free(old);
                self.cache.entries[cache_index] = copy;
                staged[i] = null;
            }
        }
        for (atoms, cache_indices[0..count]) |*atom, cache_index| {
            atom.* = self.cache.get(cache_index) orelse return error.InvalidAtomCacheRef;
        }
        return .{ .consumed = pos, .atoms = atoms };
    }

    fn findSequence(self: *Decoder, id: u64) ?usize {
        for (self.sequences.items, 0..) |sequence, i| if (sequence.id == id) return i;
        return null;
    }

    fn consume(self: *Decoder, count: usize) void {
        const remaining = self.buffer.items.len - count;
        std.mem.copyForwards(u8, self.buffer.items[0..remaining], self.buffer.items[count..]);
        self.buffer.shrinkRetainingCapacity(remaining);
    }
};

const HeaderKind = enum { normal, fragment_start, fragment_continuation };

fn writeHeader(writer: *compat.Io.Writer, kind: HeaderKind, sequence: u64, fragment: u64, refs: []const AtomCacheReference) !void {
    try writer.writeByte(codec.version);
    try writer.writeByte(switch (kind) {
        .normal => 68,
        .fragment_start => 69,
        .fragment_continuation => 70,
    });
    if (kind != .normal) {
        try writeInt(writer, u64, sequence);
        try writeInt(writer, u64, fragment);
    }
    if (kind == .fragment_continuation) return;
    if (refs.len > 255) return error.InvalidAtomCacheRef;
    try writer.writeByte(@intCast(refs.len));
    if (refs.len == 0) return;
    const flag_count = refs.len / 2 + 1;
    var flags: [128]u8 = @splat(0);
    var long_atoms = false;
    for (refs, 0..) |ref, i| {
        var nibble: u8 = @intCast(ref.cache_index / 256);
        if (ref.is_new) nibble |= 8;
        if (i % 2 == 0) flags[i / 2] |= nibble else flags[i / 2] |= nibble << 4;
        if (ref.is_new and ref.atom.len > 255) long_atoms = true;
    }
    if (long_atoms) {
        if (refs.len % 2 == 0) flags[flag_count - 1] |= 1 else flags[flag_count - 1] |= 0x10;
    }
    try writer.writeAll(flags[0..flag_count]);
    for (refs) |ref| {
        try writer.writeByte(@truncate(ref.cache_index));
        if (ref.is_new) {
            if (long_atoms) {
                if (ref.atom.len > std.math.maxInt(u16)) return error.AtomTooLong;
                try writeInt(writer, u16, @intCast(ref.atom.len));
            } else {
                if (ref.atom.len > std.math.maxInt(u8)) return error.AtomTooLong;
                try writer.writeByte(@intCast(ref.atom.len));
            }
            try writer.writeAll(ref.atom);
        }
    }
}

fn makeFrame(allocator: std.mem.Allocator, parts: []const []const u8, max_size: usize) ![]u8 {
    var size: usize = 0;
    for (parts) |part| size = std.math.add(usize, size, part.len) catch return error.SizeLimit;
    if (size > max_size or size > std.math.maxInt(u32)) return error.FrameTooLarge;
    const allocation_size = std.math.add(usize, size, 4) catch return error.FrameTooLarge;
    const frame = try allocator.alloc(u8, allocation_size);
    std.mem.writeInt(u32, frame[0..4], @intCast(size), .big);
    var at: usize = 4;
    for (parts) |part| {
        @memcpy(frame[at..][0..part.len], part);
        at += part.len;
    }
    return frame;
}

fn controlAsTerm(allocator: std.mem.Allocator, control: ControlMessage) !Term {
    if (control == .unknown) {
        const cloned = try control.unknown.clone(allocator);
        if (cloned != .tuple) {
            var invalid = cloned;
            invalid.deinit(allocator);
            return error.InvalidControlMessage;
        }
        return cloned;
    }
    const opcode = control.opcode().?;
    const args = control.args().?;
    const tuple = try allocator.alloc(Term, args.len + 1);
    tuple[0] = .{ .integer = @intFromEnum(opcode) };
    @memcpy(tuple[1..], args);
    return .{ .tuple = tuple };
}

fn validArity(opcode: Opcode, count: usize, args: []const Term) bool {
    return switch (opcode) {
        .node_link => count == 0,
        .link, .send, .unlink, .group_leader, .send_sender, .payload_exit, .payload_exit2, .alias_send => count == 2,
        .exit, .reg_send, .exit2, .send_tt, .monitor_p, .demonitor_p, .send_sender_tt, .payload_exit_tt, .payload_exit2_tt, .payload_monitor_p_exit, .alias_send_tt, .unlink_id, .unlink_id_ack => count == 3,
        .exit_tt, .reg_send_tt, .exit2_tt, .monitor_p_exit, .spawn_reply => count == 4,
        .spawn_request, .spawn_reply_tt => count == 5,
        .spawn_request_tt => count == 6,
        .altact_sig_send => if (count == 3 or count == 4) blk: {
            if (args.len == 0 or args[0] != .integer) break :blk false;
            if (args[0].integer < 0) break :blk false;
            break :blk (args[0].integer & 2 != 0) == (count == 4);
        } else false,
    };
}

fn referenceUsesSlot(refs: []const AtomCacheReference, slot: u11) bool {
    for (refs) |ref| if (ref.cache_index == slot) return true;
    return false;
}

fn freeStagedReferences(allocator: std.mem.Allocator, refs: []const AtomCacheReference) void {
    for (refs) |ref| if (ref.is_new) allocator.free(ref.atom);
}

fn collectAtoms(allocator: std.mem.Allocator, atoms: *compat.ArrayList([]const u8), term: Term) !void {
    switch (term) {
        .atom => |atom| {
            for (atoms.items) |existing| if (std.mem.eql(u8, atom, existing)) return;
            if (atoms.items.len < 255) try atoms.append(allocator, atom);
        },
        .pid => |value| try appendAtom(allocator, atoms, value.node),
        .port => |value| try appendAtom(allocator, atoms, value.node),
        .reference => |value| try appendAtom(allocator, atoms, value.node),
        .tuple => |items| for (items) |item| try collectAtoms(allocator, atoms, item),
        .map => |entries| for (entries) |entry| {
            try collectAtoms(allocator, atoms, entry.key);
            try collectAtoms(allocator, atoms, entry.value);
        },
        .list => |value| {
            for (value.elements) |item| try collectAtoms(allocator, atoms, item);
            if (value.tail) |tail| try collectAtoms(allocator, atoms, tail.*);
        },
        .new_fun => |value| {
            try appendAtom(allocator, atoms, value.module);
            try appendAtom(allocator, atoms, value.pid.node);
            for (value.free_vars) |item| try collectAtoms(allocator, atoms, item);
        },
        .legacy_fun => |value| {
            try appendAtom(allocator, atoms, value.module);
            try appendAtom(allocator, atoms, value.pid.node);
            for (value.free_vars) |item| try collectAtoms(allocator, atoms, item);
        },
        .@"export" => |value| {
            try appendAtom(allocator, atoms, value.module);
            try appendAtom(allocator, atoms, value.function);
        },
        .record => |value| {
            try appendAtom(allocator, atoms, value.module);
            try appendAtom(allocator, atoms, value.name);
            for (value.field_names) |name| try appendAtom(allocator, atoms, name);
            for (value.values) |item| try collectAtoms(allocator, atoms, item);
        },
        else => {},
    }
}

fn appendAtom(allocator: std.mem.Allocator, atoms: *compat.ArrayList([]const u8), atom: []const u8) !void {
    for (atoms.items) |existing| if (std.mem.eql(u8, atom, existing)) return;
    if (atoms.items.len < 255) try atoms.append(allocator, atom);
}

fn containsRecord(term: Term) bool {
    return switch (term) {
        .record => true,
        .tuple => |items| for (items) |item| {
            if (containsRecord(item)) break true;
        } else false,
        .map => |entries| for (entries) |entry| {
            if (containsRecord(entry.key) or containsRecord(entry.value)) break true;
        } else false,
        .list => |value| blk: {
            for (value.elements) |item| if (containsRecord(item)) break :blk true;
            if (value.tail) |tail| if (containsRecord(tail.*)) break :blk true;
            break :blk false;
        },
        .new_fun => |value| for (value.free_vars) |item| {
            if (containsRecord(item)) break true;
        } else false,
        .legacy_fun => |value| for (value.free_vars) |item| {
            if (containsRecord(item)) break true;
        } else false,
        else => false,
    };
}

fn cloneAtomRefs(allocator: std.mem.Allocator, refs: []const []const u8) ![][]u8 {
    const out = try allocator.alloc([]u8, refs.len);
    var initialized: usize = 0;
    errdefer freeAtomRefs(allocator, out[0..initialized]);
    for (refs, 0..) |atom, i| {
        out[i] = try allocator.dupe(u8, atom);
        initialized += 1;
    }
    return out;
}

fn freeAtomRefs(allocator: std.mem.Allocator, refs: [][]u8) void {
    for (refs) |atom| allocator.free(atom);
    allocator.free(refs);
}

fn refsAsConst(allocator: std.mem.Allocator, refs: [][]u8) ![][]const u8 {
    const out = try allocator.alloc([]const u8, refs.len);
    for (refs, 0..) |atom, i| out[i] = atom;
    return out;
}

fn deinitTerms(items: []Term, allocator: std.mem.Allocator) void {
    for (items) |*item| item.deinit(allocator);
    allocator.free(items);
}

fn writeInt(writer: *compat.Io.Writer, comptime T: type, value: T) !void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .big);
    try writer.writeAll(&bytes);
}

test "chunked normal frame, tick, and atom cache reuse" {
    const allocator = std.testing.allocator;
    const flags = CapabilityFlags{ .bits = CapabilityFlags.fragments | CapabilityFlags.unlink_id | CapabilityFlags.utf8_atoms | CapabilityFlags.dist_hdr_atom_cache };
    var encoder = Encoder.init(allocator, flags, .{});
    defer encoder.deinit();
    var decoder = Decoder.init(allocator, flags, .{});
    defer decoder.deinit();

    var args = try allocator.alloc(Term, 2);
    args[0] = .{ .atom = try allocator.dupe(u8, "sender") };
    args[1] = .{ .atom = try allocator.dupe(u8, "receiver") };
    var control = ControlMessage{ .link = .{ .terms = args } };
    defer control.deinit(allocator);
    var frames = try encoder.encode(control, null);
    defer frames.deinit(allocator);
    try decoder.feed(frames.items[0][0..2]);
    try std.testing.expect((try decoder.next()) == null);
    try decoder.feed(frames.items[0][2..]);
    var message = (try decoder.next()).?;
    defer message.deinit(allocator);
    try std.testing.expect(message == .data);
    try std.testing.expect(message.data.control == .link);

    const tick = try encoder.encodeTick();
    defer allocator.free(tick);
    try decoder.feed(tick);
    var tick_message = (try decoder.next()).?;
    defer tick_message.deinit(allocator);
    try std.testing.expect(tick_message == .tick);
}
