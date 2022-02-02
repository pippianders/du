// SPDX-FileCopyrightText: 2021-2022 Yoran Heling <projects@yorhel.nl>
// SPDX-License-Identifier: MIT

const std = @import("std");
const main = @import("main.zig");
const model = @import("model.zig");
const ui = @import("ui.zig");
const util = @import("util.zig");
const c_statfs = @cImport(@cInclude("sys/vfs.h"));
const c_fnmatch = @cImport(@cInclude("fnmatch.h"));

var file_writer: ?*FileWriter = null;
var items_seen: u32 = 0;
var last_level: ?*Level = null;
var last_error = std.ArrayList(u8).init(main.allocator);
var fatal_error: ?anyerror = null;

const FileWriter = std.io.BufferedWriter(4096, std.fs.File.Writer);
const Special = enum { err, other_fs, kernfs, excluded };


// Concise stat struct for fields we're interested in, with the types used by the model.
const Stat = struct {
    blocks: model.Blocks = 0,
    size: u64 = 0,
    dev: u64 = 0,
    ino: u64 = 0,
    nlink: u31 = 0,
    hlinkc: bool = false,
    dir: bool = false,
    reg: bool = true,
    symlink: bool = false,
    ext: model.Ext = .{},

    fn clamp(comptime T: type, comptime field: anytype, x: anytype) std.meta.fieldInfo(T, field).field_type {
        return util.castClamp(std.meta.fieldInfo(T, field).field_type, x);
    }

    fn truncate(comptime T: type, comptime field: anytype, x: anytype) std.meta.fieldInfo(T, field).field_type {
        return util.castTruncate(std.meta.fieldInfo(T, field).field_type, x);
    }

    fn read(parent: std.fs.Dir, name: [:0]const u8, follow: bool) !Stat {
        const stat = try std.os.fstatatZ(parent.fd, name, if (follow) 0 else std.os.AT.SYMLINK_NOFOLLOW);
        return Stat{
            .blocks = clamp(Stat, .blocks, stat.blocks),
            .size = clamp(Stat, .size, stat.size),
            .dev = truncate(Stat, .dev, stat.dev),
            .ino = truncate(Stat, .ino, stat.ino),
            .nlink = clamp(Stat, .nlink, stat.nlink),
            .hlinkc = stat.nlink > 1 and !std.os.system.S.ISDIR(stat.mode),
            .dir = std.os.system.S.ISDIR(stat.mode),
            .reg = std.os.system.S.ISREG(stat.mode),
            .symlink = std.os.system.S.ISLNK(stat.mode),
            .ext = .{
                .mtime = clamp(model.Ext, .mtime, stat.mtime().tv_sec),
                .uid = truncate(model.Ext, .uid, stat.uid),
                .gid = truncate(model.Ext, .gid, stat.gid),
                .mode = truncate(model.Ext, .mode, stat.mode),
            },
        };
    }
};


fn writeErr(e: anyerror) noreturn {
    ui.die("Error writing to file: {s}.\n", .{ ui.errorString(e) });
}

// Output a JSON string.
// Could use std.json.stringify(), but that implementation is "correct" in that
// it refuses to encode non-UTF8 slices as strings. Ncdu dumps aren't valid
// JSON if we have non-UTF8 filenames, such is life...
fn writeJsonString(wr: anytype, s: []const u8) !void {
    try wr.writeByte('"');
    for (s) |ch| {
        switch (ch) {
            '\n' => try wr.writeAll("\\n"),
            '\r' => try wr.writeAll("\\r"),
            0x8  => try wr.writeAll("\\b"),
            '\t' => try wr.writeAll("\\t"),
            0xC  => try wr.writeAll("\\f"),
            '\\' => try wr.writeAll("\\\\"),
            '"'  => try wr.writeAll("\\\""),
            0...7, 0xB, 0xE...0x1F, 127 => try wr.print("\\u00{x:02}", .{ch}),
            else => try wr.writeByte(ch)
        }
    }
    try wr.writeByte('"');
}

fn writeSpecial(w: anytype, name: []const u8, t: Special, isdir: bool) !void {
    try w.writeAll(",\n");
    if (isdir) try w.writeByte('[');
    try w.writeAll("{\"name\":");
    try writeJsonString(w, name);
    switch (t) {
        .err => try w.writeAll(",\"read_error\":true"),
        .other_fs => try w.writeAll(",\"excluded\":\"othfs\""),
        .kernfs => try w.writeAll(",\"excluded\":\"kernfs\""),
        .excluded => try w.writeAll(",\"excluded\":\"pattern\""),
    }
    try w.writeByte('}');
    if (isdir) try w.writeByte(']');
}

fn writeStat(w: anytype, name: []const u8, stat: *const Stat, read_error: bool, dir_dev: u64) !void {
    try w.writeAll(",\n");
    if (stat.dir) try w.writeByte('[');
    try w.writeAll("{\"name\":");
    try writeJsonString(w, name);
    if (stat.size > 0) try w.print(",\"asize\":{d}", .{ stat.size });
    if (stat.blocks > 0) try w.print(",\"dsize\":{d}", .{ util.blocksToSize(stat.blocks) });
    if (stat.dir and stat.dev != 0 and stat.dev != dir_dev) try w.print(",\"dev\":{d}", .{ stat.dev });
    if (stat.hlinkc) try w.print(",\"ino\":{d},\"hlnkc\":true,\"nlink\":{d}", .{ stat.ino, stat.nlink });
    if (!stat.dir and !stat.reg) try w.writeAll(",\"notreg\":true");
    if (read_error) try w.writeAll(",\"read_error\":true");
    if (main.config.extended)
        try w.print(",\"uid\":{d},\"gid\":{d},\"mode\":{d},\"mtime\":{d}",
            .{ stat.ext.uid, stat.ext.gid, stat.ext.mode, stat.ext.mtime });
    try w.writeByte('}');
}


// A MemDir represents an in-memory directory listing (i.e. model.Dir) where
// entries read from disk can be merged into, without doing an O(1) lookup for
// each entry.
const MemDir = struct {
    dir: ?*model.Dir,

    // Lookup table for name -> *entry.
    // null is never stored in the table, but instead used pass a name string
    // as out-of-band argument for lookups.
    entries: Map,
    const Map = std.HashMap(?*model.Entry, void, HashContext, 80);

    const HashContext = struct {
        cmp: []const u8 = "",

        pub fn hash(self: @This(), v: ?*model.Entry) u64 {
            return std.hash.Wyhash.hash(0, if (v) |e| @as([]const u8, e.name()) else self.cmp);
        }

        pub fn eql(self: @This(), ap: ?*model.Entry, bp: ?*model.Entry) bool {
            if (ap == bp) return true;
            const a = if (ap) |e| @as([]const u8, e.name()) else self.cmp;
            const b = if (bp) |e| @as([]const u8, e.name()) else self.cmp;
            return std.mem.eql(u8, a, b);
        }
    };

    const Self = @This();

    fn init(dir: ?*model.Dir) Self {
        var self = Self{
            .dir = dir,
            .entries = Map.initContext(main.allocator, HashContext{}),
        };

        var count: Map.Size = 0;
        var it = if (dir) |d| d.sub else null;
        while (it) |e| : (it = e.next) count += 1;
        self.entries.ensureUnusedCapacity(count) catch unreachable;

        it = if (dir) |d| d.sub else null;
        while (it) |e| : (it = e.next)
            self.entries.putAssumeCapacity(e, @as(void,undefined));
        return self;
    }

    fn addSpecial(self: *Self, name: []const u8, t: Special) void {
        var dir = self.dir orelse unreachable; // root can't be a Special
        var e = blk: {
            if (self.entries.getEntryAdapted(@as(?*model.Entry,null), HashContext{ .cmp = name })) |entry| {
                // XXX: If the type doesn't match, we could always do an
                // in-place conversion to a File entry. That's more efficient,
                // but also more code. I don't expect this to happen often.
                var e = entry.key_ptr.*.?;
                if (e.etype == .file) {
                    if (e.size > 0 or e.blocks > 0) {
                        e.delStats(dir);
                        e.size = 0;
                        e.blocks = 0;
                        e.addStats(dir, 0);
                    }
                    e.file().?.resetFlags();
                    _ = self.entries.removeAdapted(@as(?*model.Entry,null), HashContext{ .cmp = name });
                    break :blk e;
                } else e.delStatsRec(dir);
            }
            var e = model.Entry.create(.file, false, name);
            e.next = dir.sub;
            dir.sub = e;
            e.addStats(dir, 0);
            break :blk e;
        };
        var f = e.file().?;
        switch (t) {
            .err => e.setErr(dir),
            .other_fs => f.other_fs = true,
            .kernfs => f.kernfs = true,
            .excluded => f.excluded = true,
        }
    }

    fn addStat(self: *Self, name: []const u8, stat: *const Stat) *model.Entry {
        const etype = if (stat.dir) model.EType.dir
                      else if (stat.hlinkc) model.EType.link
                      else model.EType.file;
        var e = blk: {
            if (self.entries.getEntryAdapted(@as(?*model.Entry,null), HashContext{ .cmp = name })) |entry| {
                // XXX: In-place conversion may also be possible here.
                var e = entry.key_ptr.*.?;
                // changes of dev/ino affect hard link counting in a way we can't simply merge.
                const samedev = if (e.dir()) |d| d.dev == model.devices.getId(stat.dev) else true;
                const sameino = if (e.link()) |l| l.ino == stat.ino else true;
                if (e.etype == etype and samedev and sameino) {
                    _ = self.entries.removeAdapted(@as(?*model.Entry,null), HashContext{ .cmp = name });
                    break :blk e;
                } else e.delStatsRec(self.dir.?);
            }
            var e = model.Entry.create(etype, main.config.extended, name);
            if (self.dir) |d| {
                e.next = d.sub;
                d.sub = e;
            } else
                model.root = e.dir() orelse unreachable;
            break :blk e;
        };
        // Ignore the new size/blocks field for directories, as we don't know
        // what the original values were without calling delStats() on the
        // entire subtree, which, in turn, would break all shared hardlink
        // sizes. The current approach may result in incorrect sizes after
        // refresh, but I expect the difference to be fairly minor.
        if (!(e.etype == .dir and e.counted) and (e.blocks != stat.blocks or e.size != stat.size)) {
            if (self.dir) |d| e.delStats(d);
            e.blocks = stat.blocks;
            e.size = stat.size;
        }
        if (e.dir()) |d| {
            d.parent = self.dir;
            d.dev = model.devices.getId(stat.dev);
        }
        if (e.file()) |f| {
            f.resetFlags();
            f.notreg = !stat.dir and !stat.reg;
        }
        if (e.link()) |l| l.ino = stat.ino;
        if (e.ext()) |ext| {
            const mtime = ext.mtime;
            ext.* = stat.ext;
            if (mtime > ext.mtime) ext.mtime = mtime;
        }

        if (self.dir) |d| e.addStats(d, stat.nlink);
        return e;
    }

    fn final(self: *Self) void {
        if (self.entries.count() == 0) // optimization for the common case
            return;
        var dir = self.dir orelse return;
        var it = &dir.sub;
        while (it.*) |e| {
            if (self.entries.contains(e)) {
                e.delStatsRec(dir);
                it.* = e.next;
            } else
                it = &e.next;
        }
    }

    fn deinit(self: *Self) void {
        self.entries.deinit();
    }
};


// Abstract "directory level" API for processing scan/import results and
// assembling those into an in-memory representation for browsing or to a JSON
// format for exporting.
const Level = struct {
    sub: ?*Level = null,
    parent: ?*Level = null,
    ctx: Ctx,

    const Ctx = union(enum) {
        mem: MemDir,
        file: File,
    };

    const File = struct {
        // buffer for entries we can output once the sub-levels are finished.
        buf: std.ArrayList(u8) = std.ArrayList(u8).init(main.allocator),
        dir_dev: u64,
        name: []u8, // Separate allocation, only used for reporting
    };

    const LevelWriter = std.io.Writer(*Level, FileWriter.Error || error{OutOfMemory}, Level.write);

    fn write(self: *Level, bytes: []const u8) !usize {
        if (self.sub == null) return try file_writer.?.write(bytes);
        switch (self.ctx) {
            Ctx.mem => unreachable,
            Ctx.file => |*f| {
                f.buf.appendSlice(bytes) catch unreachable;
                return bytes.len;
            }
        }
    }

    fn writer(self: *Level) LevelWriter {
        return .{ .context = self };
    }

    fn fmtPath(self: *Level, out: *std.ArrayList(u8)) void {
        switch (self.ctx) {
            Ctx.mem => |m| {
                if (m.dir) |d| d.fmtPath(true, out)
                else out.append('/') catch unreachable;
            },
            Ctx.file => |f| {
                if (self.parent) |p| {
                    p.fmtPath(out);
                    out.append('/') catch unreachable;
                }
                out.appendSlice(f.name) catch unreachable;
            },
        }
    }

    fn addSpecial(self: *Level, name: []const u8, t: Special, isdir: bool) void {
        if (t == .err and main.config.scan_ui.? != .none) {
            last_error.clearRetainingCapacity();
            self.fmtPath(&last_error);
            last_error.append('/') catch unreachable;
            last_error.appendSlice(name) catch unreachable;
        }

        switch (self.ctx) {
            Ctx.mem => |*m| m.addSpecial(name, t),
            Ctx.file => writeSpecial(self.writer(), name, t, isdir) catch |e| writeErr(e),
        }
        items_seen += 1;
    }

    // (can also be used for empty dirs)
    fn addFile(self: *Level, name: []const u8, stat: *const Stat, read_error: bool) void {
        switch (self.ctx) {
            Ctx.mem => |*m| _ = m.addStat(name, stat),
            Ctx.file => {
                writeStat(self.writer(), name, stat, read_error, 0) catch |e| writeErr(e);
                if (stat.dir) self.writer().writeByte(']') catch |e| writeErr(e);
            },
        }
        items_seen += 1;
    }

    fn addDir(self: *Level, name: []const u8, stat: *const Stat, list_error: bool, sub_lvl: *Level) void {
        std.debug.assert(stat.dir);
        std.debug.assert(self.sub == null); // We don't support disjoint trees, that would require extra buffering.
        switch (self.ctx) {
            Ctx.mem => |*m| {
                const dir = m.addStat(name, stat).dir() orelse unreachable;
                if (list_error) dir.entry.setErr(dir);
                sub_lvl.* = .{ .parent = self, .ctx = .{ .mem = MemDir.init(dir) } };
            },
            Ctx.file => |f| {
                writeStat(self.writer(), name, stat, list_error, f.dir_dev) catch |e| writeErr(e);
                sub_lvl.* = .{ .parent = self, .ctx = .{ .file = .{
                    .dir_dev = stat.dev,
                    .name = main.allocator.dupe(u8, name) catch unreachable,
                } } };
            },
        }
        self.sub = sub_lvl;
        last_level = sub_lvl;
        items_seen += 1;
    }

    fn close(self: *Level) void {
        std.debug.assert(self.sub == null);
        switch (self.ctx) {
            Ctx.mem => |*m| {
                m.final();
                m.deinit();
            },
            Ctx.file => |*f| {
                file_writer.?.writer().writeAll(f.buf.items) catch |e| writeErr(e);
                file_writer.?.writer().writeByte(']') catch |e| writeErr(e);
                f.buf.deinit();
                main.allocator.free(f.name);
            },
        }
        if (self.parent) |p| {
            p.sub = null;
            last_level = p;
            switch (p.ctx) {
                Ctx.file => |*f| {
                    file_writer.?.writer().writeAll(f.buf.items) catch |e| writeErr(e);
                    f.buf.clearRetainingCapacity();
                },
                else => {},
            }
        } else {
            switch (self.ctx) {
                Ctx.mem => {
                    counting_hardlinks = true;
                    defer counting_hardlinks = false;
                    main.handleEvent(false, true);
                    model.inodes.addAllStats();
                },
                Ctx.file => {
                    var w = file_writer.?;
                    w.flush() catch |e| writeErr(e);
                    main.allocator.destroy(w);
                },
            }
        }
        self.* = undefined;
    }
};

fn initFile(out: std.fs.File, lvl: *Level) void {
    var buf = main.allocator.create(FileWriter) catch unreachable;
    errdefer main.allocator.destroy(buf);
    buf.* = std.io.bufferedWriter(out.writer());
    var wr = buf.writer();
    wr.writeAll("[1,2,{\"progname\":\"ncdu\",\"progver\":\"" ++ main.program_version ++ "\",\"timestamp\":") catch |e| writeErr(e);
    wr.print("{d}", .{std.time.timestamp()}) catch |e| writeErr(e);
    wr.writeByte('}') catch |e| writeErr(e);

    file_writer = buf;
    lvl.* = .{ .ctx = Level.Ctx{ .file = .{
        .dir_dev = 0,
        .name = main.allocator.dupe(u8, "") catch unreachable,
    } } };

    last_error.clearRetainingCapacity();
    last_level = lvl;
    fatal_error = null;
    items_seen = 0;
}

fn initMem(dir: ?*model.Dir, lvl: *Level) void {
    lvl.* = .{ .ctx = Level.Ctx{ .mem = MemDir.init(dir) } };

    last_error.clearRetainingCapacity();
    last_level = lvl;
    fatal_error = null;
    items_seen = 0;
}


// This function only works on Linux
fn isKernfs(dir: std.fs.Dir, dev: u64) bool {
    const state = struct {
        var cache = std.AutoHashMap(u64,bool).init(main.allocator);
        var lock = std.Thread.Mutex{};
    };
    state.lock.lock();
    defer state.lock.unlock();
    if (state.cache.get(dev)) |e| return e;
    var buf: c_statfs.struct_statfs = undefined;
    if (c_statfs.fstatfs(dir.fd, &buf) != 0) return false; // silently ignoring errors isn't too nice.
    const iskern = switch (buf.f_type) {
        // These numbers are documented in the Linux 'statfs(2)' man page, so I assume they're stable.
        0x42494e4d, // BINFMTFS_MAGIC
        0xcafe4a11, // BPF_FS_MAGIC
        0x27e0eb, // CGROUP_SUPER_MAGIC
        0x63677270, // CGROUP2_SUPER_MAGIC
        0x64626720, // DEBUGFS_MAGIC
        0x1cd1, // DEVPTS_SUPER_MAGIC
        0x9fa0, // PROC_SUPER_MAGIC
        0x6165676c, // PSTOREFS_MAGIC
        0x73636673, // SECURITYFS_MAGIC
        0xf97cff8c, // SELINUX_MAGIC
        0x62656572, // SYSFS_MAGIC
        0x74726163 // TRACEFS_MAGIC
        => true,
        else => false,
    };
    state.cache.put(dev, iskern) catch {};
    return iskern;
}

// The following filesystem scanning implementation is designed to support
// some degree of parallelism while generating a serialized tree without
// consuming ~too~ much memory.
//
// It would likely be easier and more efficient to have each thread work on a
// completely sparate branch of the filesystem tree, but our current JSON
// export format requires that entries are output in a certain order, which
// means we either need to construct the full tree in memory before generating
// any output (which I'd really rather not do), or we're stuck scanning the
// filesystem in the required order and lose some opportunities for
// parallelism. This is an attempt at doing the latter.
const scanner = struct {
    var tail: *Dir = undefined;
    var head: *Dir = undefined;
    // Currently used to protect both the scan stack state and the output
    // context, may be worth trying to split in two.
    var lock = std.Thread.Mutex{};
    var cond = std.Thread.Condition{};

    // Number of stat() calls to batch in a single task; This little thread
    // pool implementation is pretty damn inefficient, so batching helps cut
    // down on synchronization overhead. Can be removed if we ever manage to
    // migrate to a more efficient thread pool.
    const BATCH: usize = 128;

    // Maximum number of name lists to keep for each level in the stack. Higher
    // number means potentially higher degree of parallelism, but comes at the
    // cost of potentially higher memory and file descriptor use.
    const SUBDIRS_PER_LEVEL: u8 = 8;

    const StatEntry = struct {
        name: [:0]u8,
        stat: Stat,
    };

    const SpecialEntry = struct {
        name: [:0]u8,
        t: Special,
    };

    const NextDir = struct {
        name: [:0]u8,
        stat: Stat,
        fd: std.fs.Dir,
        names: std.ArrayListUnmanaged([:0]u8) = .{},
        specials: std.ArrayListUnmanaged(SpecialEntry) = .{},
        list_error: bool = false,
    };

    // Represents a directory that is being scanned.
    const Dir = struct {
        lvl: Level = undefined,
        fd: std.fs.Dir,
        dir_dev: u64,
        names: std.ArrayListUnmanaged([:0]u8) = .{}, // Queue of names to stat()
        names_busy: u8 = 0, // Number of threads running stat()
        dirs: std.ArrayListUnmanaged(StatEntry) = .{}, // Queue of dirs we can read
        dirs_busy: u8 = 0, // Number of 'dirs' being processed at the moment
        next: std.ArrayListUnmanaged(NextDir) = .{}, // Queue of subdirs to scan next

        // Assumption: all queues are empty
        fn destroy(dir: *Dir) void {
            dir.fd.close();
            dir.names.deinit(main.allocator);
            dir.dirs.deinit(main.allocator);
            dir.next.deinit(main.allocator);
            main.allocator.destroy(dir);
        }
    };

    // Leave the current dir if we're done with it and find a new dir to enter.
    fn navigate() void {
        //std.debug.print("ctx={s}, names={} dirs={} next={}\n", .{ active_context.path.items, tail.names.items.len, tail.dirs.items.len, tail.next.items.len });

        while (tail != head
            and tail.names.items.len == 0 and tail.names_busy == 0
            and tail.dirs.items.len == 0 and tail.dirs_busy == 0
            and tail.next.items.len == 0
        ) {
            //std.debug.print("Pop\n", .{});
            const dir = tail;
            tail = @fieldParentPtr(Dir, "lvl", dir.lvl.parent.?);
            dir.lvl.close();
            dir.destroy();
        }
        if (tail.next.items.len > 0) {
            var next_sub = tail.next.pop();
            var sub = main.allocator.create(Dir) catch unreachable;
            sub.* = .{
                .fd = next_sub.fd,
                .dir_dev = next_sub.stat.dev,
                .names = next_sub.names,
            };
            tail.lvl.addDir(next_sub.name, &next_sub.stat, next_sub.list_error, &sub.lvl);
            outputNextDirSpecials(&next_sub, &sub.lvl);
            main.allocator.free(next_sub.name);
            tail = sub;
        }

        // TODO: Only wake up threads when there's enough new work queued, all
        // that context switching is SLOW.
        cond.broadcast();
    }

    fn readNamesDir(dir: *NextDir) void {
        var it = dir.fd.iterate();
        while (true) {
            const entry = it.next() catch {
                dir.list_error = true;
                break;
            } orelse break;

            // TODO: Check for exclude patterns

            dir.names.append(main.allocator, main.allocator.dupeZ(u8, entry.name) catch unreachable) catch unreachable;
        }
    }

    fn outputNextDirSpecials(dir: *NextDir, lvl: *Level) void {
        for (dir.specials.items) |e| {
            lvl.addSpecial(e.name, e.t, false);
            main.allocator.free(e.name);
        }
        dir.specials.deinit(main.allocator);
    }

    fn readNames(parent: *Dir) void {
        const stat = parent.dirs.pop();
        lock.unlock();

        var fd = parent.fd.openDirZ(stat.name, .{ .access_sub_paths = true, .iterate = true, .no_follow = true }) catch {
            lock.lock();
            parent.lvl.addSpecial(stat.name, .err, true);
            main.allocator.free(stat.name);
            return;
        };

        if (@import("builtin").os.tag == .linux and main.config.exclude_kernfs and isKernfs(fd, stat.stat.dev)) {
            lock.lock();
            parent.lvl.addSpecial(stat.name, .kernfs, true);
            main.allocator.free(stat.name);
            return;
        }

        if (main.config.exclude_caches) {
            if (fd.openFileZ("CACHEDIR.TAG", .{})) |f| {
                const sig = "Signature: 8a477f597d28d172789f06886806bc55";
                var buf: [sig.len]u8 = undefined;
                if (f.reader().readAll(&buf)) |len| {
                    if (len == sig.len and std.mem.eql(u8, &buf, sig)) {
                        lock.lock();
                        parent.lvl.addSpecial(stat.name, .excluded, true);
                        main.allocator.free(stat.name);
                        return;
                    }
                } else |_| {}
            } else |_| {}
        }

        var dir = NextDir{ .name = stat.name, .fd = fd, .stat = stat.stat };
        readNamesDir(&dir);

        lock.lock();
        if (dir.names.items.len == 0 and dir.specials.items.len == 0) {
            parent.lvl.addFile(stat.name, &stat.stat, dir.list_error);
            main.allocator.free(stat.name);
            fd.close();
        } else {
            parent.next.append(main.allocator, dir) catch unreachable;
        }
    }

    fn statNames(dir: *Dir) void {
        var names: [BATCH][:0]u8 = undefined;
        var stats: [BATCH]Stat = undefined;
        var errs: [BATCH]bool = undefined;
        const len = std.math.min(names.len, dir.names.items.len);
        std.mem.copy([]u8, &names, dir.names.items[dir.names.items.len-len..]);
        dir.names.items.len -= len;
        lock.unlock();

        var i: usize = 0;
        while (i < len) : (i += 1) {
            if (Stat.read(dir.fd, names[i], false)) |s| {
                errs[i] = false;
                if (main.config.follow_symlinks and s.symlink) {
                    if (Stat.read(dir.fd, names[i], true)) |nstat| {
                        if (!nstat.dir) {
                            stats[i] = nstat;
                            // Symlink targets may reside on different filesystems,
                            // this will break hardlink detection and counting so let's disable it.
                            if (nstat.hlinkc and nstat.dev != dir.dir_dev)
                                stats[i].hlinkc = false;
                        }
                    } else |_| stats[i] = s;
                } else stats[i] = s;

            } else |_|
                errs[i] = true;
        }

        lock.lock();
        i = 0;
        while (i < len) : (i += 1) {
            if (errs[i]) {
                dir.lvl.addSpecial(names[i], .err, false);
                main.allocator.free(names[i]);
            } else if (main.config.same_fs and stats[i].dev != dir.dir_dev) {
                dir.lvl.addSpecial(names[i], .other_fs, stats[i].dir);
                main.allocator.free(names[i]);
            } else if (stats[i].dir) {
                dir.dirs.append(main.allocator, .{ .name = names[i], .stat = stats[i] }) catch unreachable;
            } else {
                dir.lvl.addFile(names[i], &stats[i], false);
                main.allocator.free(names[i]);
            }
        }
    }

    fn runThread(main_thread: bool) void {
        lock.lock();
        outer: while (true) {

            if (main_thread and (items_seen & 128) == 0) {
                lock.unlock();
                main.handleEvent(false, false);
                lock.lock();
            }

            var dir = tail;
            while (true) {
                // If we have subdirectories to read, do that first to keep the 'names' queues filled up.
                if (dir.dirs.items.len > 0 and dir.dirs_busy + dir.next.items.len < SUBDIRS_PER_LEVEL) {
                    dir.dirs_busy += 1;
                    readNames(dir);
                    dir.dirs_busy -= 1;
                    navigate();
                    continue :outer;
                }

                // Then look for names to stat
                if (dir.names.items.len > 0) {
                    dir.names_busy += 1;
                    statNames(dir);
                    dir.names_busy -= 1;
                    navigate();
                    continue :outer;
                }

                if (dir == head) break
                else dir = @fieldParentPtr(Dir, "lvl", dir.lvl.parent.?);
            }

            // If we're here, then we found no work to do.
            if (tail == head and tail.dirs_busy == 0 and tail.names_busy == 0) {
                cond.broadcast(); // only necessary if we don't always wake up threads when there's work to do.
                break;
            }
            cond.wait(&lock);
        }
        lock.unlock();
    }

    // Open the given path and scan it into *Dir.
    fn scan(dir: *Dir, path: [:0]const u8) void {
        tail = dir;
        head = dir;
        dir.fd = std.fs.cwd().openDirZ(path, .{ .access_sub_paths = true, .iterate = true }) catch |e| {
            last_error.appendSlice(path) catch unreachable;
            fatal_error = e;
            while (main.state == .refresh or main.state == .scan)
                main.handleEvent(true, true);
            return;
        };

        var next_dir = NextDir{ .name = undefined, .stat = undefined, .fd = dir.fd };
        readNamesDir(&next_dir);
        outputNextDirSpecials(&next_dir, &dir.lvl);
        dir.names = next_dir.names;

        var threads = main.allocator.alloc(std.Thread, main.config.parallel-1) catch unreachable;
        for (threads) |*t| t.* = std.Thread.spawn(.{ .stack_size = 128*1024 }, runThread, .{false}) catch unreachable;
        runThread(true);
        for (threads) |*t| t.join();
        main.allocator.free(threads);
        head.lvl.close();
        head.destroy();
        head = undefined;
        tail = undefined;
    }
};


pub fn scanRoot(orig_path: [:0]const u8, out: ?std.fs.File) !void {
    var lvl: Level = undefined;
    if (out) |f| initFile(f, &lvl) else initMem(null, &lvl);

    var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const full_path =
        if (std.os.realpathZ(orig_path, &buf)) |p| main.allocator.dupeZ(u8, p) catch unreachable
        else |_| null;
    defer if (full_path) |p| main.allocator.free(p);
    const path = full_path orelse orig_path;

    const stat = try Stat.read(std.fs.cwd(), path, true);
    if (!stat.dir) return error.NotDir;

    var sub = main.allocator.create(scanner.Dir) catch unreachable;
    sub.* = .{ .fd = undefined, .dir_dev = undefined };
    lvl.addDir(path, &stat, false, &sub.lvl);
    sub.dir_dev = stat.dev;
    scanner.scan(sub, path);
    lvl.close();
}

pub fn refresh(parent: *model.Dir) void {
    var full_path = std.ArrayList(u8).init(main.allocator);
    defer full_path.deinit();
    parent.fmtPath(true, &full_path);

    var sub = main.allocator.create(scanner.Dir) catch unreachable;
    sub.* = .{ .fd = undefined, .dir_dev = model.devices.list.items[parent.dev] };
    initMem(parent, &sub.lvl);
    scanner.scan(sub, util.arrayListBufZ(&full_path));
}


// Using a custom recursive descent JSON parser here. std.json is great, but
// has two major downsides:
// - It does strict UTF-8 validation. Which is great in general, but not so
//   much for ncdu dumps that may contain non-UTF-8 paths encoded as strings.
// - The streaming parser requires complex and overly large buffering in order
//   to read strings, which doesn't work so well in our case.
//
// TODO: This code isn't very elegant and is likely contains bugs. It may be
// worth factoring out the JSON parts into a separate abstraction for which
// tests can be written.
const Import = struct {
    rd: std.fs.File,
    rdoff: usize = 0,
    rdsize: usize = 0,
    rdbuf: [8*1024]u8 = undefined,

    ch: u8 = 0, // last read character, 0 = EOF (or invalid null byte, who cares)
    byte: u64 = 1,
    line: u64 = 1,
    namebuf: [32*1024]u8 = undefined,
    statbuf: Stat = undefined,
    root_level: Level = undefined,

    const Self = @This();

    fn die(self: *Self, str: []const u8) noreturn {
        ui.die("Error importing file on line {}:{}: {s}.\n", .{ self.line, self.byte, str });
    }

    // Advance to the next byte, sets ch.
    fn con(self: *Self) void {
        if (self.rdoff >= self.rdsize) {
            self.rdoff = 0;
            self.rdsize = self.rd.read(&self.rdbuf) catch |e| switch (e) {
                error.InputOutput => self.die("I/O error"),
                error.IsDir => self.die("not a file"), // should be detected at open() time, but no flag for that...
                error.SystemResources => self.die("out of memory"),
                else => unreachable,
            };
            if (self.rdsize == 0) {
                self.ch = 0;
                return;
            }
        }
        self.ch = self.rdbuf[self.rdoff];
        self.rdoff += 1;
        self.byte += 1;
    }

    // Advance to the next non-whitespace byte.
    fn conws(self: *Self) void {
        while (true) {
            switch (self.ch) {
                '\n' => {
                    self.line += 1;
                    self.byte = 1;
                },
                ' ', '\t', '\r' => {},
                else => break,
            }
            self.con();
        }
    }

    // Returns the current byte and advances to the next.
    fn next(self: *Self) u8 {
        defer self.con();
        return self.ch;
    }

    fn hexdig(self: *Self) u16 {
        return switch (self.ch) {
            '0'...'9' => self.next() - '0',
            'a'...'f' => self.next() - 'a' + 10,
            'A'...'F' => self.next() - 'A' + 10,
            else => self.die("invalid hex digit"),
        };
    }

    // Read a string into buf.
    // Any characters beyond the size of the buffer are consumed but otherwise discarded.
    // (May store fewer characters in the case of \u escapes, it's not super precise)
    fn string(self: *Self, buf: []u8) []u8 {
        if (self.next() != '"') self.die("expected '\"'");
        var n: usize = 0;
        while (true) {
            const ch = self.next();
            switch (ch) {
                '"' => break,
                '\\' => switch (self.next()) {
                    '"' => if (n < buf.len) { buf[n] = '"'; n += 1; },
                    '\\'=> if (n < buf.len) { buf[n] = '\\';n += 1; },
                    '/' => if (n < buf.len) { buf[n] = '/'; n += 1; },
                    'b' => if (n < buf.len) { buf[n] = 0x8; n += 1; },
                    'f' => if (n < buf.len) { buf[n] = 0xc; n += 1; },
                    'n' => if (n < buf.len) { buf[n] = 0xa; n += 1; },
                    'r' => if (n < buf.len) { buf[n] = 0xd; n += 1; },
                    't' => if (n < buf.len) { buf[n] = 0x9; n += 1; },
                    'u' => {
                        const char = (self.hexdig()<<12) + (self.hexdig()<<8) + (self.hexdig()<<4) + self.hexdig();
                        if (n + 6 < buf.len)
                            n += std.unicode.utf8Encode(char, buf[n..n+5]) catch unreachable;
                    },
                    else => self.die("invalid escape sequence"),
                },
                0x20, 0x21, 0x23...0x5b, 0x5d...0xff => if (n < buf.len) { buf[n] = ch; n += 1; },
                else => self.die("invalid character in string"),
            }
        }
        return buf[0..n];
    }

    fn uint(self: *Self, T: anytype) T {
        if (self.ch == '0') {
            self.con();
            return 0;
        }
        var v: T = 0;
        while (self.ch >= '0' and self.ch <= '9') {
            const newv = v *% 10 +% (self.ch - '0');
            if (newv < v) self.die("integer out of range");
            v = newv;
            self.con();
        }
        if (v == 0) self.die("expected number");
        return v;
    }

    fn boolean(self: *Self) bool {
        switch (self.next()) {
            't' => {
                if (self.next() == 'r' and self.next() == 'u' and self.next() == 'e')
                    return true;
            },
            'f' => {
                if (self.next() == 'a' and self.next() == 'l' and self.next() == 's' and self.next() == 'e')
                    return false;
            },
            else => {}
        }
        self.die("expected boolean");
    }

    // Consume and discard any JSON value.
    fn conval(self: *Self) void {
        switch (self.ch) {
            't' => _ = self.boolean(),
            'f' => _ = self.boolean(),
            'n' => {
                self.con();
                if (!(self.next() == 'u' and self.next() == 'l' and self.next() == 'l'))
                    self.die("invalid JSON value");
            },
            '"' => _ = self.string(&[0]u8{}),
            '{' => {
                self.con();
                self.conws();
                if (self.ch == '}') { self.con(); return; }
                while (true) {
                    self.conws();
                    _ = self.string(&[0]u8{});
                    self.conws();
                    if (self.next() != ':') self.die("expected ':'");
                    self.conws();
                    self.conval();
                    self.conws();
                    switch (self.next()) {
                        ',' => continue,
                        '}' => break,
                        else => self.die("expected ',' or '}'"),
                    }
                }
            },
            '[' => {
                self.con();
                self.conws();
                if (self.ch == ']') { self.con(); return; }
                while (true) {
                    self.conws();
                    self.conval();
                    self.conws();
                    switch (self.next()) {
                        ',' => continue,
                        ']' => break,
                        else => self.die("expected ',' or ']'"),
                    }
                }
            },
            '-', '0'...'9' => {
                self.con();
                // Numbers are kind of annoying, this "parsing" is invalid and ultra-lazy.
                while (true) {
                    switch (self.ch) {
                        '-', '+', 'e', 'E', '.', '0'...'9' => self.con(),
                        else => return,
                    }
                }
            },
            else => self.die("invalid JSON value"),
        }
    }

    fn itemkey(self: *Self, key: []const u8, name: *?[]u8, special: *?Special) void {
        const eq = std.mem.eql;
        switch (if (key.len > 0) key[0] else @as(u8,0)) {
            'a' => {
                if (eq(u8, key, "asize")) {
                    self.statbuf.size = self.uint(u64);
                    return;
                }
            },
            'd' => {
                if (eq(u8, key, "dsize")) {
                    self.statbuf.blocks = @intCast(model.Blocks, self.uint(u64)>>9);
                    return;
                }
                if (eq(u8, key, "dev")) {
                    self.statbuf.dev = self.uint(u64);
                    return;
                }
            },
            'e' => {
                if (eq(u8, key, "excluded")) {
                    var buf: [32]u8 = undefined;
                    const typ = self.string(&buf);
                    // "frmlnk" is also possible, but currently considered equivalent to "pattern".
                    if (eq(u8, typ, "otherfs")) special.* = .other_fs
                    else if (eq(u8, typ, "kernfs")) special.* = .kernfs
                    else special.* = .excluded;
                    return;
                }
            },
            'g' => {
                if (eq(u8, key, "gid")) {
                    self.statbuf.ext.gid = self.uint(u32);
                    return;
                }
            },
            'h' => {
                if (eq(u8, key, "hlnkc")) {
                    self.statbuf.hlinkc = self.boolean();
                    return;
                }
            },
            'i' => {
                if (eq(u8, key, "ino")) {
                    self.statbuf.ino = self.uint(u64);
                    return;
                }
            },
            'm' => {
                if (eq(u8, key, "mode")) {
                    self.statbuf.ext.mode = self.uint(u16);
                    return;
                }
                if (eq(u8, key, "mtime")) {
                    self.statbuf.ext.mtime = self.uint(u64);
                    // Accept decimal numbers, but discard the fractional part because our data model doesn't support it.
                    if (self.ch == '.') {
                        self.con();
                        while (self.ch >= '0' and self.ch <= '9')
                            self.con();
                    }
                    return;
                }
            },
            'n' => {
                if (eq(u8, key, "name")) {
                    if (name.* != null) self.die("duplicate key");
                    name.* = self.string(&self.namebuf);
                    if (name.*.?.len > self.namebuf.len-5) self.die("too long file name");
                    return;
                }
                if (eq(u8, key, "nlink")) {
                    self.statbuf.nlink = self.uint(u31);
                    if (!self.statbuf.dir and self.statbuf.nlink > 1)
                        self.statbuf.hlinkc = true;
                    return;
                }
                if (eq(u8, key, "notreg")) {
                    self.statbuf.reg = !self.boolean();
                    return;
                }
            },
            'r' => {
                if (eq(u8, key, "read_error")) {
                    if (self.boolean())
                        special.* = .err;
                    return;
                }
            },
            'u' => {
                if (eq(u8, key, "uid")) {
                    self.statbuf.ext.uid = self.uint(u32);
                    return;
                }
            },
            else => {},
        }
        self.conval();
    }

    fn iteminfo(self: *Self, dir_dev: u64, lvl: *Level, sub: *Level) void {
        if (self.next() != '{') self.die("expected '{'");
        self.statbuf.dev = dir_dev;
        var name: ?[]u8 = null;
        var special: ?Special = null;
        while (true) {
            self.conws();
            var keybuf: [32]u8 = undefined;
            const key = self.string(&keybuf);
            self.conws();
            if (self.next() != ':') self.die("expected ':'");
            self.conws();
            self.itemkey(key, &name, &special);
            self.conws();
            switch (self.next()) {
                ',' => continue,
                '}' => break,
                else => self.die("expected ',' or '}'"),
            }
        }
        const nname = name orelse self.die("missing \"name\" field");
        if (self.statbuf.dir) lvl.addDir(nname, &self.statbuf, if (special) |s| s == .err else false, sub)
        else if (special) |s| lvl.addSpecial(nname, s, self.statbuf.dir)
        else lvl.addFile(nname, &self.statbuf, false);
    }

    fn item(self: *Self, lvl: *Level, dev: u64) void {
        self.statbuf = .{};
        var isdir = false;
        if (self.ch == '[') {
            isdir = true;
            self.statbuf.dir = true;
            self.con();
            self.conws();
        }

        var sub: Level = undefined;
        self.iteminfo(dev, lvl, &sub);

        self.conws();
        if (isdir) {
            while (self.ch == ',') {
                self.con();
                self.conws();
                self.item(&sub, self.statbuf.dev);
                self.conws();
            }
            if (self.next() != ']') self.die("expected ',' or ']'");
            sub.close();
        }

        if ((items_seen & 1023) == 0)
            main.handleEvent(false, false);
    }

    fn root(self: *Self) void {
        self.con();
        self.conws();
        if (self.next() != '[') self.die("expected '['");
        self.conws();
        if (self.uint(u16) != 1) self.die("incompatible major format version");
        self.conws();
        if (self.next() != ',') self.die("expected ','");
        self.conws();
        _ = self.uint(u16); // minor version, ignored for now
        self.conws();
        if (self.next() != ',') self.die("expected ','");
        self.conws();
        // metadata object
        if (self.ch != '{') self.die("expected '{'");
        self.conval(); // completely discarded
        self.conws();
        if (self.next() != ',') self.die("expected ','");
        self.conws();
        // root element
        if (self.ch != '[') self.die("expected '['"); // top-level entry must be a dir
        self.item(&self.root_level, 0);
        self.conws();
        // any trailing elements
        while (self.ch == ',') {
            self.con();
            self.conws();
            self.conval();
            self.conws();
        }
        if (self.next() != ']') self.die("expected ',' or ']'");
        self.conws();
        if (self.ch != 0) self.die("trailing garbage");
    }
};

pub fn importRoot(path: [:0]const u8, out: ?std.fs.File) void {
    var fd = if (std.mem.eql(u8, "-", path)) std.io.getStdIn()
             else std.fs.cwd().openFileZ(path, .{})
                  catch |e| ui.die("Error reading file: {s}.\n", .{ui.errorString(e)});
    defer fd.close();

    var imp = Import{ .rd = fd };
    if (out) |f| initFile(f, &imp.root_level)
    else initMem(null, &imp.root_level);
    imp.root();
    imp.root_level.close();
}



var animation_pos: u32 = 0;
var counting_hardlinks: bool = false;
var need_confirm_quit = false;

fn drawError(err: anyerror) void {
    const width = ui.cols -| 5;
    const box = ui.Box.create(7, width, "Scan error");

    box.move(2, 2);
    ui.addstr("Path: ");
    ui.addstr(ui.shorten(ui.toUtf8(util.arrayListBufZ(&last_error)), width -| 10));

    box.move(3, 2);
    ui.addstr("Error: ");
    ui.addstr(ui.shorten(ui.errorString(err), width -| 6));

    box.move(5, width -| 27);
    ui.addstr("Press any key to continue");
}

fn drawCounting() void {
    const box = ui.Box.create(4, 25, "Finalizing");
    box.move(2, 2);
    ui.addstr("Counting hardlinks...");
}

fn drawBox() void {
    ui.init();
    if (fatal_error) |err| return drawError(err);
    if (counting_hardlinks) return drawCounting();

    scanner.lock.lock();
    defer scanner.lock.unlock();

    const width = ui.cols -| 5;
    const box = ui.Box.create(10, width, "Scanning...");
    box.move(2, 2);
    ui.addstr("Total items: ");
    ui.addnum(.default, items_seen);

    if (width > 48 and items_seen > 0) {
        box.move(2, 30);
        ui.addstr("size: ");
        // TODO: Should display the size of the dir-to-be-refreshed on refreshing, not the root.
        ui.addsize(.default, util.blocksToSize(model.root.entry.blocks +| model.inodes.total_blocks));
    }

    if (last_level) |l| {
        box.move(3, 2);
        ui.addstr("Current dir: ");
        var path = std.ArrayList(u8).init(main.allocator);
        defer path.deinit();
        l.fmtPath(&path);
        ui.addstr(ui.shorten(ui.toUtf8(util.arrayListBufZ(&path)), width -| 18));
    }

    if (last_error.items.len > 0) {
        box.move(5, 2);
        ui.style(.bold);
        ui.addstr("Warning: ");
        ui.style(.default);
        ui.addstr("error scanning ");
        ui.addstr(ui.shorten(ui.toUtf8(util.arrayListBufZ(&last_error)), width -| 28));
        box.move(6, 3);
        ui.addstr("some directory sizes may not be correct.");
    }

    if (need_confirm_quit) {
        box.move(8, width -| 20);
        ui.addstr("Press ");
        ui.style(.key);
        ui.addch('y');
        ui.style(.default);
        ui.addstr(" to confirm");
    } else {
        box.move(8, width -| 18);
        ui.addstr("Press ");
        ui.style(.key);
        ui.addch('q');
        ui.style(.default);
        ui.addstr(" to abort");
    }

    if (main.config.update_delay < std.time.ns_per_s and width > 40) {
        const txt = "Scanning...";
        animation_pos += 1;
        if (animation_pos >= txt.len*2) animation_pos = 0;
        if (animation_pos < txt.len) {
            var i: u32 = 0;
            box.move(8, 2);
            while (i <= animation_pos) : (i += 1) ui.addch(txt[i]);
        } else {
            var i: u32 = txt.len-1;
            while (i > animation_pos-txt.len) : (i -= 1) {
                box.move(8, 2+i);
                ui.addch(txt[i]);
            }
        }
    }
}

pub fn draw() void {
    if (fatal_error != null and main.config.scan_ui.? != .full)
        ui.die("Error reading {s}: {s}\n", .{ last_error.items, ui.errorString(fatal_error.?) });
    switch (main.config.scan_ui.?) {
        .none => {},
        .line => {
            var buf: [256]u8 = undefined;
            var line: []const u8 = undefined;
            {
                scanner.lock.lock();
                defer scanner.lock.unlock();
                var path = std.ArrayList(u8).init(main.allocator);
                defer path.deinit();
                if (last_level) |l| l.fmtPath(&path);
                const pathZ = util.arrayListBufZ(&path);

                if (counting_hardlinks) {
                    line = "\x1b7\x1b[JCounting hardlinks...\x1b8";
                } else if (file_writer != null) {
                    line = std.fmt.bufPrint(&buf, "\x1b7\x1b[J{s: <63} {d:>9} files\x1b8",
                        .{ ui.shorten(pathZ, 63), items_seen }
                    ) catch return;
                } else {
                    const r = ui.FmtSize.fmt(util.blocksToSize(model.root.entry.blocks));
                    line = std.fmt.bufPrint(&buf, "\x1b7\x1b[J{s: <51} {d:>9} files / {s}{s}\x1b8",
                        .{ ui.shorten(pathZ, 51), items_seen, r.num(), r.unit }
                    ) catch return;
                }
            }
            _ = std.io.getStdErr().write(line) catch {};
        },
        .full => drawBox(),
    }
}

pub fn keyInput(ch: i32) void {
    if (fatal_error != null) {
        if (main.state == .scan) ui.quit()
        else main.state = .browse;
        return;
    }
    if (need_confirm_quit) {
        switch (ch) {
            'y', 'Y' => if (need_confirm_quit) ui.quit(),
            else => need_confirm_quit = false,
        }
        return;
    }
    switch (ch) {
        'q' => if (main.config.confirm_quit) { need_confirm_quit = true; } else ui.quit(),
        else => need_confirm_quit = false,
    }
}
