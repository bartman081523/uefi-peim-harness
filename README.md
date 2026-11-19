# uefi-peim-harness

A minimal **32-bit UEFI PEIM** (PEI module, PE32 / `pei-i386`) execution harness built on
[Unicorn](https://www.unicorn-engine.org/) and [Capstone](https://www.capstone-engine.org/).

Qiling's UEFI loader (`QlLoaderPE_UEFI`) is 64-bit/DXE-oriented and refuses PE32 modules
(`qlErrorArch: Only 64-bit modules are supported at the moment`). This harness is a small,
transparent substitute that focuses on **PEI-phase behaviour**: PEI service dispatch, PPI
registration, and the actual SMBus transactions a PEIM performs after it is loaded.

It was developed while reverse-engineering a production AMI Aptio firmware image, and it
reproduces the entry path of `SmBusPei` bit-for-bit-comparable across firmware revisions.

## What it does

1. Loads a PE32 image at its `ImageBase` (sections read directly via
   `PointerToRawData`/`SizeOfRawData`; `pefile.get_data()` misreads synthetic TE→PE32 files).
2. Installs a **logging fake `EFI_PEI_SERVICES` table** (128 slots, one distinct stub each)
   and calls the entry with `(Handle=0, &PeiServices)`.
3. Emulates the AMI-style **allocate service** at `table+0x4c`
   (`(This, size, *out)` → bump allocator), so the PEIM can build its PPI structures.
4. Logs every PEI service slot call, heap allocation, PPI installation, and MMIO access in
   the AMD FCH SMBus window (`0xFED80000..+0x2000`).
5. Optionally **calls the installed SMBus PPI** (`--exec`) and traces the real ISA-IO
   transaction on the SMBus host controller.

## Requirements

```bash
python3 -m pip install -r requirements.txt
```

Tested with Python 3.12, Unicorn 2.1.4, Capstone 5.0.9.

## Usage

```bash
# Run the module entry point only
python unicorn_peim.py <module.pe.bin> [max_insns]

# After the entry, call the installed SMBus PPI Execute handler
# default operation = 4 (EfiSmbusReadByte), slave = 0x50, command = 0x00
python unicorn_peim.py <module.pe.bin> [max_insns] --exec [operation] [slave] [command]

# Supply SPD data; the ReadByte reply is spd[command]
python unicorn_peim.py <module.pe.bin> 200000 --exec 4 0x50 0x02 --spd "12 34 56 78"
python unicorn_peim.py <module.pe.bin> 200000 --exec 4 0x50 0x00 --spd @spd.bin
```

Examples:

```bash
python unicorn_peim.py SmBusPei.pe.bin 8000000
python unicorn_peim.py SmBusPei.pe.bin 200000 --exec            # ReadByte, 0x50, 0x00
python unicorn_peim.py SmBusPei.pe.bin 200000 --exec 4 0x51 0x10
```

If an image installs several PPI candidates, select one with the `PEIM_PPI_INDEX`
environment variable (`0` by default):

```bash
PEIM_PPI_INDEX=2 python unicorn_peim.py SmBusPei.pe.bin 200000 --exec
```

### Getting a `module.pe.bin`

Extract the PEIM from a firmware volume (e.g. UEFITool / `uefi-firmware-parser`) and keep the
PE32 body (the section data, not the FFS header). If the module is stored as **TE** (Terse
Executable), convert it to PE32 first. The harness expects a normal PE32 image whose section
table is valid; it does not parse TE headers.

## Output

```
module: SmBusPei.pe.bin
ImageBase=0x9de8000 entry=0x9decfb0 SizeOfImage=0x1700 max_insns=8000000
run...
  slot 19 (table+0x4c) esp=... args=...      # allocate
  ...
  ENTRY RETURNED (clean ret to caller)
PEI service calls: 40
slot histogram: {6: 8, 8: 8, 9: 8, 19: 16}
allocations: [...]
SMBus PPI This=0x90001060 Execute=0x9ded436
=== calling SMBus PPI Execute(op=4, slave=0x50, cmd=0x0, len=1) ===
Execute eax: 0x0                              # EFI_SUCCESS
```

## Emulation details worth knowing

Unicorn 2.1.x cannot hook `RDTSC`, `RDMSR`, or arbitrary instructions through
`UC_HOOK_INSN` (only `IN`/`OUT`/`SYSCALL`/`SYSENTER`/`CPUID`). The harness therefore:

- **Capstone-scans** the executable sections for `rdtsc` / `rdmsr` and installs **code hooks**
  that set `EAX:EDX` and skip the instruction (`EIP += 2`).
- Supplies a **valid AMD P-state MSR** for `0xC0010064..0xC001006B` (bit 63 set, plausible
  CpuFid/CpuDfsId). Without it, the firmware's TSC-frequency detection treats every P-state
  as invalid and retries forever. (`uc.msr_write()` in this Unicorn version does *not* affect
  the `rdmsr` instruction.)
- Skips the **`RDTSC` delay helper** (entry = `min(rdtsc address) - 1`) by returning from it
  immediately: hardware timing is irrelevant for logic tracing.
- Installs **x86 IO-port hooks** (`IN`/`OUT`). The SMBus host controller is IO-decoded at
  **`0x0B00`**; register 0 is the host status word and bit 0 is `HostBusy`. The hook reports
  an idle/error-free controller (`0x00`) so the driver's `in al,dx` poll terminates.
- Emulates the **PPI notify service** (`table+0x20`): its 5th argument is an out-pointer that
  must receive a parent function table. Some revisions dispatch their delay/ARP path through
  that table; without it, the run faults on a NULL vtable.

## SMBus PPI

The registered PPI is a `0x58`-byte allocation whose first four dwords are in-image code
pointers:

| Offset | Role |
|-------:|------|
| `+0x00` | `Execute` |
| `+0x04` | `ArpDevice` |
| `+0x08` | `GetArpMap` |
| `+0x0c` | `Notify` (returns `EFI_UNSUPPORTED`) |

The harness discovers the interface dynamically (first `0x58` allocation with four valid
in-image pointers), so it works across images with different load addresses. `--exec` calls
`Execute(This, SlaveAddress, Command, Operation, PecCheck, Length*, Buffer*)` using the cdecl
convention (the standard `EFI_PEI_SMBUS_PPI_EXECUTE_OPERATION` order).

Observed transaction (ReadByte, slave `0x50`, command `0x00`, with the standard
`Execute(This, SlaveAddress, Command, Operation, PecCheck, Length*, Buffer*)` order):

```
; controller init / bus-free
R 0x0B08                         ; bus-free status
W 0x0B08 = 0xFF
R 0x00ED ; R 0x00ED              ; AMD delay port
R 0x0B08                         ; bit 4 (0x10) set -> bus free
W 0x0B00 = 0x1F                  ; clear status bits
R 0x0B00 = 0x00                  ; HostBusy cleared
W 0x0B01 = 0x3F                  ; control/enable

; ReadByte transaction (0x0B03 command, 0x0B04 address, 0x0B05 data)
W 0x0B04 = 0xA1                  ; SlaveAddress 0x50 << 1 | Read
W 0x0B03 = 0x00                  ; Command
W 0x0B02 = 0x48                  ; host control: start + ReadByte protocol
R 0x0B05 = 0x12                  ; host data 0  -> caller buffer
W 0x0B02 = 0x00                  ; control reset
```

With the sample data byte, `Execute` returns `EFI_SUCCESS` and the caller's buffer contains
`0x12` (`len=1`).

## Limitations

- The PEI-services table is **AMI-extended**, not the standard `PiPeiCis` order
  (slot `0x4c` is allocate in these images). Slot names beyond the observed ones are inferred.
- No real PEI core, no HOBs, no memory map — services are stubs/loggers.
- The SMBus **data byte is a fixed sample** (`0x12` on registers `0x0B04/0x0B05`). Address
  and command are derived correctly from the PPI arguments, but real SPD contents require
  feeding the actual DIMM data into the `0x0B05` read.
- Different firmware revisions can expose several PPI instances. On the tested image,
  index `0` is the SMBus PPI (returns `EFI_SUCCESS`), index `1` is a second SMBus instance
  with no responding device (`EFI_TIMEOUT`), and indexes `2/3` are a different PPI class
  that rejects the parameters (`EFI_INVALID_PARAMETER`). Use `PEIM_PPI_INDEX` to select one.

## Docs

- `docs/peim_dynamic_exec.md` — dynamic execution notes (Qiling vs. Unicorn, entry trace,
  SMBus PPI emulation results).
- `docs/smbuspei_fib_vs_fid.md` — differential analysis of two firmware revisions.

## License

MIT — see `LICENSE`.
