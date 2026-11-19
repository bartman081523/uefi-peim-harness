#!/usr/bin/env python3
"""Minimal 32-bit PEIM harness: load a PE32 image at its ImageBase, install a
logging fake EFI_PEI_SERVICES table with per-slot handlers, and run the entry
point. Logs which PEI service slots are called and stops at the first fault.

Service slot 19 (table+0x4c) behaves like an allocate-and-return-pointer
service: it is given (This, size, *out) and the caller reads the pointer from
*out afterwards. We emulate that with a bump allocator so the PEIM can proceed.

Usage: unicorn_peim.py <module.pe.bin> [max_insns]
"""
import sys
from pefile import PE
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UC_HOOK_INSN
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import (
    UC_X86_REG_ESP,
    UC_X86_REG_EIP,
    UC_X86_REG_EAX,
    UC_X86_REG_EDX,
    UC_X86_INS_RDTSC,
)

path = sys.argv[1]
max_insns = int(sys.argv[2]) if len(sys.argv) > 2 else 5_000_000

raw = open(path, "rb").read()
pe = PE(path)
ib = pe.OPTIONAL_HEADER.ImageBase
entry = ib + pe.OPTIONAL_HEADER.AddressOfEntryPoint
size_of_image = pe.OPTIONAL_HEADER.SizeOfImage


def section_bytes(s):
    start = s.PointerToRawData
    return raw[start:start + s.SizeOfRawData]


STACK = 0x70000000
TABLE = 0x80000000
STUBS = 0x81000000
PPS = 0x82000000
SCRATCH = 0x90000000
SCRATCH_SIZE = 0x400000
NSLOT = 128
STUB_STRIDE = 8
ALLOC_SLOT = 19  # table+0x4c
NOTIFY_SLOT = 8  # table+0x20: installs a notify table; out-arg5 receives a vtable
VTABLE = TABLE + 0x800  # fake parent table used by the PPI ARP wrapper

uc = Uc(UC_ARCH_X86, UC_MODE_32)


def align_down(x): return x & ~0xfff
def align_up(x): return (x + 0xfff) & ~0xfff


img_base = align_down(ib)
img_end = align_up(ib + size_of_image)
uc.mem_map(img_base, img_end - img_base)
uc.mem_write(ib, raw[:pe.OPTIONAL_HEADER.SizeOfHeaders])
for s in pe.sections:
    data = section_bytes(s)
    if data:
        uc.mem_write(ib + s.VirtualAddress, data)

uc.mem_map(STACK, 0x100000)
uc.mem_map(TABLE, 0x1000)
uc.mem_map(STUBS, 0x1000)
uc.mem_map(PPS, 0x1000)
uc.mem_map(SCRATCH, SCRATCH_SIZE)
# AMD FCH SMBus MMIO window (0xFED80300 base); map it zeroed so status reads work.
FCH_SMBUS = 0xFED80000
uc.mem_map(FCH_SMBUS, 0x2000)

for i in range(NSLOT):
    uc.mem_write(STUBS + i * STUB_STRIDE, bytes([0xB8, 0, 0, 0, 0, 0xC3, 0x90, 0x90]))
    uc.mem_write(TABLE + i * 4, (STUBS + i * STUB_STRIDE).to_bytes(4, "little"))
uc.mem_write(PPS, TABLE.to_bytes(4, "little"))

# The PPI notify service hands back a "parent" table via an out-parameter; the
# ARP wrapper later calls [parent+4]. Provide a table whose method returns 0
# (the slot-0 stub is `mov eax,0; ret`).
uc.mem_write(VTABLE, (0).to_bytes(4, "little"))
uc.mem_write(VTABLE + 4, (STUBS).to_bytes(4, "little"))


def u32(addr): return int.from_bytes(uc.mem_read(addr, 4), "little")
def w32(addr, val): uc.mem_write(addr, val.to_bytes(4, "little"))


calls = []
instr_count = [0]
bump = [SCRATCH + 0x1000]
alloc_log = []
returned = [False]


def hook_stub(uc_, address, size, _):
    idx = (address - STUBS) // STUB_STRIDE
    calls.append(idx)
    if len(calls) > 200000:
        uc_.emu_stop()
        return
    esp = uc_.reg_read(UC_X86_REG_ESP)
    if idx == ALLOC_SLOT:
        this = u32(esp + 4)
        req = u32(esp + 8)
        outp = u32(esp + 0xc)
        n = (req + 0xf) & ~0xf
        ptr = bump[0]
        bump[0] += n
        if bump[0] > SCRATCH + SCRATCH_SIZE:
            print(f"  ALLOC overflow req={req:#x}")
            uc_.emu_stop()
            return
        if outp != 0 and (outp & 0xfff) and (TABLE <= outp < TABLE + 0x1000 or PPS <= outp < PPS + 0x1000):
            w32(outp, ptr)
        elif outp != 0:
            try:
                w32(outp, ptr)
            except Exception:
                pass
        alloc_log.append((req, ptr))
        if len(alloc_log) <= 20:
            print(f"  slot {idx} ALLOC size={req:#x} -> {ptr:#x} (this={this:#x})")
    elif idx == NOTIFY_SLOT:
        # Out-argument 5 is &[ppi+0x20]; hand back the fake parent table so the
        # PPI's ARP/dispatch wrapper has a valid vtable instead of NULL.
        outp = u32(esp + 0x14)
        if outp:
            try:
                w32(outp, VTABLE)
            except Exception:
                pass
        if len(calls) <= 40:
            print(f"  slot {idx} NOTIFY (table+{idx*4:#x}) out={outp:#x} -> {VTABLE:#x}")
    elif len(calls) <= 40:
        print(f"  slot {idx} (table+{idx*4:#x}) esp={esp:#x} args={u32(esp+4):#x},{u32(esp+8):#x},{u32(esp+0xc):#x}")


def hook_code(uc_, address, size, _):
    instr_count[0] += 1
    if instr_count[0] >= max_insns:
        uc_.emu_stop()


def hook_unmapped(uc_, access, address, size, value, _):
    if address == 0xDEADBEEF:
        returned[0] = True
        print("  ENTRY RETURNED (clean ret to caller)")
        uc_.emu_stop()
        return True
    print(f"  UNMAPPED access={access} addr={address:#x} size={size}")
    return False


def hook_mmio(uc_, access, address, size, value, _):
    if access == UC_HOOK_MEM_READ:
        val = int.from_bytes(uc_.mem_read(address, size), "little")
        print(f"  SMBUS R [{address:#x}] size={size} = {val:#x}")
    else:
        print(f"  SMBUS W [{address:#x}] size={size} = {value:#x}")
    return True


uc.hook_add(UC_HOOK_CODE, hook_stub, None, STUBS, STUBS + NSLOT * STUB_STRIDE)
uc.hook_add(UC_HOOK_CODE, hook_code)
uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)

# Unicorn 2.1.4 cannot hook RDTSC/RDMSR via UC_HOOK_INSN (only IN/OUT/SYSCALL/
# CPUID), so locate them with Capstone and emulate them via code hooks.
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

_tsc = [0]


def hook_rdtsc(uc_, address, size, user_data):
    _tsc[0] = (_tsc[0] + 0x1000) & 0xFFFFFFFFFFFFFFFF
    uc_.reg_write(UC_X86_REG_EAX, _tsc[0] & 0xFFFFFFFF)
    uc_.reg_write(UC_X86_REG_EDX, (_tsc[0] >> 32) & 0xFFFFFFFF)
    uc_.reg_write(UC_X86_REG_EIP, address + 2)


from unicorn.x86_const import UC_X86_REG_ECX

# AMD P-state MSR 0xC0010064: bit63 valid, CpuDfsId(bits13:8)=8, CpuFid(bits7:0)=0x18
_PSTATE_MSR = 0x8000000000000000 | (0x08 << 8) | 0x18


def hook_rdmsr(uc_, address, size, user_data):
    msr = uc_.reg_read(UC_X86_REG_ECX)
    val = _PSTATE_MSR if 0xC0010064 <= msr <= 0xC001006B else 0
    uc_.reg_write(UC_X86_REG_EAX, val & 0xFFFFFFFF)
    uc_.reg_write(UC_X86_REG_EDX, (val >> 32) & 0xFFFFFFFF)
    uc_.reg_write(UC_X86_REG_EIP, address + 2)


_rdtsc_addrs = []
_rdmsr_addrs = []
_md = Cs(CS_ARCH_X86, CS_MODE_32)
for _s in pe.sections:
    _name = _s.Name.rstrip(b"\x00")
    if _s.SizeOfRawData == 0 or _name == b".reloc":
        continue
    _va = ib + _s.VirtualAddress
    try:
        _blob = bytes(uc.mem_read(_va, _s.SizeOfRawData))
    except Exception:
        continue
    for _insn in _md.disasm(_blob, _va):
        if _insn.mnemonic == "rdtsc":
            _rdtsc_addrs.append(_insn.address)
        elif _insn.mnemonic == "rdmsr":
            _rdmsr_addrs.append(_insn.address)
for _a in _rdtsc_addrs:
    uc.hook_add(UC_HOOK_CODE, hook_rdtsc, None, _a, _a + 1)
for _a in _rdmsr_addrs:
    uc.hook_add(UC_HOOK_CODE, hook_rdmsr, None, _a, _a + 1)

# The RDTSC loop is a timing-delay helper; hardware timing is irrelevant for
# logic tracing, so return from it immediately instead of spinning.
if _rdtsc_addrs:
    _delay_entry = min(_rdtsc_addrs) - 1

    def hook_skip_delay(uc_, address, size, user_data):
        _sp = uc_.reg_read(UC_X86_REG_ESP)
        _ret = int.from_bytes(uc_.mem_read(_sp, 4), "little")
        uc_.reg_write(UC_X86_REG_ESP, _sp + 4)
        uc_.reg_write(UC_X86_REG_EIP, _ret)

    uc.hook_add(UC_HOOK_CODE, hook_skip_delay, None, _delay_entry, _delay_entry + 1)
    print("delay-skip hook at:", hex(_delay_entry))
if _rdtsc_addrs:
    print("RDTSC hooks at:", [hex(a) for a in _rdtsc_addrs])
if _rdmsr_addrs:
    print("RDMSR hooks at:", [hex(a) for a in _rdmsr_addrs])
uc.hook_add(
    UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
    hook_mmio,
    None,
    FCH_SMBUS,
    FCH_SMBUS + 0x2000,
)

# x86 IO-port hooks: the SMBus poll loop reads a status register via `in al,dx`
# and spins until bit 0x10 is set. Unicorn has no IO backend, so provide one.
from unicorn.x86_const import UC_X86_INS_IN, UC_X86_INS_OUT

io_log = []
io_state = {}


def hook_in(uc_, port, size, user_data):
    size = size or 1
    # AMD FCH SMBus host controller at IO base 0x0B00:
    #   0x0B00 status (bit0 HostBusy), 0x0B01 control, 0x0B02 host command,
    #   0x0B03 host address, 0x0B04/0x0B05 host data.
    # Report an idle, error-free controller and a sample SPD data byte, so the
    # driver's poll and data phase both make progress.
    if port in (0x0B00, 0x0B01, 0x0B02):
        val = 0x00
    elif port in (0x0B04, 0x0B05):
        val = 0x12  # sample byte (real SPD contents depend on the DIMM)
    else:
        val = (1 << (size * 8)) - 1
    io_log.append(("R", port, size, val))
    return val


def hook_out(uc_, port, size, value, user_data):
    io_state[port] = value
    io_log.append(("W", port, size, value))


uc.hook_add(UC_HOOK_INSN, hook_in, None, 1, 0, UC_X86_INS_IN)
uc.hook_add(UC_HOOK_INSN, hook_out, None, 1, 0, UC_X86_INS_OUT)

sp = STACK + 0x80000
uc.mem_write(sp, (0xDEADBEEF).to_bytes(4, "little"))
uc.mem_write(sp + 4, (0).to_bytes(4, "little"))
uc.mem_write(sp + 8, PPS.to_bytes(4, "little"))
uc.reg_write(UC_X86_REG_ESP, sp)

print(f"module: {path}")
print(f"ImageBase={ib:#x} entry={entry:#x} SizeOfImage={size_of_image:#x} max_insns={max_insns}")
print("run...")
try:
    uc.emu_start(entry, 0, timeout=0, count=max_insns)
    print("STOPPED cleanly")
except Exception as e:
    if not returned[0]:
        print(f"FAULT: {type(e).__name__}: {e}")
        try:
            print(f"  eip={uc.reg_read(UC_X86_REG_EIP):#x} eax={uc.reg_read(UC_X86_REG_EAX):#x}")
        except Exception:
            pass

if returned[0]:
    print("\n=== post-run PPI dump ===")
    for addr in (0x9dee210, 0x9dee230, 0x9dee240, 0x9dee250, 0x9dee220):
        try:
            print(f"desc@{addr:#x}:", uc.mem_read(addr, 24).hex(" "))
        except Exception as e:
            print(f"desc@{addr:#x}: <{e}>")
    for (size, ptr) in alloc_log[:16]:
        try:
            print(f"alloc@{ptr:#x} size={size:#x}:", uc.mem_read(ptr, min(size, 0x58)).hex(" "))
        except Exception:
            pass

if "--exec" in sys.argv:
    # Exercise the installed SMBus PPI Execute handler after the entry ran.
    returned[0] = False
    exec_sp = STACK + 0x60000
    lenbuf = SCRATCH + 0x200000
    buffer = SCRATCH + 0x200000 + 0x40
    uc.mem_write(lenbuf, (1).to_bytes(4, "little"))
    # Locate the installed SMBus PPI interface: a 0x58-byte allocation whose
    # first four dwords form a function table of in-image code pointers.
    _cands = []
    for (_sz, _ptr) in alloc_log:
        if _sz != 0x58:
            continue
        try:
            _fps = [int.from_bytes(uc.mem_read(_ptr + _i * 4, 4), "little") for _i in range(4)]
        except Exception:
            continue
        if all(ib <= _fp < ib + size_of_image for _fp in _fps):
            _cands.append((_ptr, _fps))
    import os

    _idx = int(os.environ.get("PEIM_PPI_INDEX", "0"))
    _this = None
    _execute = None
    if _cands:
        _this, _fps = _cands[min(_idx, len(_cands) - 1)]
        _execute = _fps[0]
    if _this is None:
        print("\nno SMBus PPI interface found; skipping Execute")
        _execute = None
    else:
        print(f"\nSMBus PPI This={_this:#x} Execute={_execute:#x}")
    # cdecl: This, SlaveAddress, Command, Operation, PecCheck, Length*, Buffer*
    # (standard EFI_PEI_SMBUS_PPI_EXECUTE_OPERATION order)
    # Optional CLI args after --exec: operation slave command (defaults: ReadByte 0x50 0x00)
    _extra = sys.argv[sys.argv.index("--exec") + 1:]
    _op = int(_extra[0], 0) if len(_extra) > 0 else 4
    _slave = int(_extra[1], 0) if len(_extra) > 1 else 0x50
    _cmd = int(_extra[2], 0) if len(_extra) > 2 else 0
    args = [_this or 0, _slave, _cmd, _op, 0, lenbuf, buffer]
    uc.mem_write(exec_sp, (0xDEADBEEF).to_bytes(4, "little"))
    for i, a in enumerate(args):
        uc.mem_write(exec_sp + 4 + i * 4, a.to_bytes(4, "little"))
    uc.reg_write(UC_X86_REG_ESP, exec_sp)
    import collections

    _trace = collections.deque(maxlen=24)
    _pc_hist = collections.Counter()

    def _trace_hook(uc_, address, size, user_data):
        _trace.append(address)
        _pc_hist[address] += 1

    _th = uc.hook_add(UC_HOOK_CODE, _trace_hook)
    print(f"\n=== calling SMBus PPI Execute(op={_op}, slave={_slave:#x}, cmd={_cmd:#x}, len=1) ===")
    _before = instr_count[0]
    _io_before = len(io_log)
    if _execute is not None:
        try:
            uc.emu_start(_execute, 0, timeout=0, count=max_insns)
            print("Execute emu_start unit returned")
        except Exception as e:
            print(f"Execute fault: {e} eip={uc.reg_read(UC_X86_REG_EIP):#x}")
    uc.hook_del(_th)
    print(
        "exec instrs:", instr_count[0] - _before,
        "eip:", hex(uc.reg_read(UC_X86_REG_EIP)),
        "esp:", hex(uc.reg_read(UC_X86_REG_ESP)),
        "returned_flag:", returned[0],
    )
    print("last pcs:", [hex(a) for a in list(_trace)[-12:]])
    print("hot pcs:", [(hex(a), c) for a, c in _pc_hist.most_common(8)])
    _exec_io = io_log[_io_before:]
    print("exec IO accesses:", len(_exec_io))
    for _ent in _exec_io[:2000]:
        _rw, _port, _sz, _val = _ent
        print(f"  IO {_rw} port={_port:#06x} size={_sz} val={_val:#x}")
    print("Execute eax:", hex(uc.reg_read(UC_X86_REG_EAX)))
    try:
        _len = int.from_bytes(uc.mem_read(lenbuf, 4), "little")
        print(f"out buffer pointer={buffer:#x} len={_len} bytes={uc.mem_read(buffer, max(1, min(_len, 16))).hex(' ')}")
    except Exception as _e:
        print("buffer dump failed:", _e)

print(f"\ninstructions executed: {instr_count[0]}")
print(f"PEI service calls: {len(calls)}")
print("slot histogram:", {k: calls.count(k) for k in sorted(set(calls))})
print("allocations:", alloc_log[:20])
