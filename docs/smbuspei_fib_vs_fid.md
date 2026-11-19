# SmBusPei FIb ↔ FId — TSC-/CPU-Frequenz-Timing-Subsystem (P-4)

**Datum:** 2026-11-19 · **Ziel:** `SmBusPei` PEIM (GUID `…0139`, `o139`) aus
`B550AORUSELITEV212.FIb` vs `…FId` · **Grad:** A (byte-genau + objdump-Disassembly)
**Artefakte:** `scratches/p4_SmBusPei_{FIb,FId}_o139.pe.bin` (TE→PE32 via `p4_te2pe.py`,
ehemaliger 8-B-Slice-Bug behoben) · Disassembly `/tmp/opencode/smbus_{fib,fid}.dis`.

## Größen / Layout

| | .text | .data | .reloc | Datei |
|---|---|---|---|---|
| FIb | `0x10FE` @ `0x9decf28` | `0xDC` @ `0x9dee028` | `0x6C` | 5152 |
| FId | `0x12DE` @ `0x9decf30` | `0xEC` @ `0x9dee210` | `0x6C` | 5664 |

Δ = +0x1E0 Byte Code (+0x10 Byte .data). Der „erste Diff @.text+0x52" der Vorsession
sind reine **Relokatios-Shifts** (`mov esi,0x9dee080→0x9dee268`, `mov [eax],0x9ded3ae→0x9ded436`),
keine Semantikänderung.

## Kernbefund: FId ergänzt ein TSC-/Frequenz-Timing-Subsystem

Am **Ende** von FId`.text` (ab `0x9dedf61`) steht ein neuer geschlossener Code-Block:

| FId-Adresse | Funktion (belegt durch Instruktionen) |
|---|---|
| `0x9dedf65` | **`udelay`** — `rdtsc`-Busy-Wait: `rdtsc; add/adc deadline; rdtsc; cmp edx:esi / eax:ecx; ja; pause; jmp` |
| `0x9dedf86` | **AMD-P-State-Frequenzerkennung** — `lea eax,[edi-0x3ffeff9c]` ⇒ **MSR `0xC0010064` (PStateDef[0])**, `rdmsr`, Schleife über 8 P-States (bit31 = PStateEn), FID/DID → MHz (`imul …0xc8`/`…0x19`, `div`), ×1 000 000 (µs) |
| `0x9dee001` | **Kalibrierung** — ruft Frequenzerkennung, dividiert durch `0xF4240` (1 Mio.), ruft `udelay`, liefert `0x32` (50) |
| `0x9dee042` | **`__allshr`** (64-bit Shift-Rechts, `shrd; shr`) |
| `0x9dee069` | **`__allmul`** (64-bit Multiply, `mul + add edx,ebx`) |
| `0x9dee088` | **`__alldiv`** (64-bit Divide, `div ecx` / `div ecx`, Rest via `[ecx]`) — **genau das von der Vorsession gesuchte Symbol** |
| `0x9dee0a5` | `int3 int3 int3` (Padding) |

Zusätzlich: FId`.text+0` (`0x9decf30`, 56 Insn) ist eine **neue Thunk-Funktion**, die per
`jmp 0x9dee088` in `__alldiv` springt (Compiler-`__aulldiv`-Einstieg); dadurch rutscht der
eigentliche PEIM-Entry-Stub von `.text+0` (FIb `0x9decf28`) auf `.text+0x80` (FId `0x9decfb0`).

## Umverdrahtete Aufrufstellen (Timing)

Zahlreiche Stellen, die in FIb feste Zählschleifen bzw. einen indirekten Service-Aufruf
(`mov eax,[edi]; push 0xc8; push eax; call [eax+4]`) nutzten, rufen in FId die kalibrierten
Helfer: `call 0x9dee001` (Kalibrierung) mehrfach, sowie `call 0x9deda9c` / `0x9dedac3` /
`0x9deddae` anstelle der alten FIb-Ziele `0x9deda14` / `0x9deda71` / `0x9dedd22`.
Die alten Delay-/Retry-Funktionen (`0x9deda3b`, `0x9deda71`) wurden dabei umstrukturiert
und an die neue 64-bit-Arithmetik angebunden.

## Deutung (Hypothese, C)

Das FId-Update ersetzt **ungenaue/feste Wartezeiten** in den SMBus-/SPD-/Flash-Pfaden durch
**TSC-kalibrierte Mikrosekunden-Delays** (Frequenz aus AMD-P-State-MSR). Das ist ein
plausibler Timing-Robustheits-Fix (SMBus-Timing/Retry) — konsistent mit einem Vendor-Bugfix
zwischen FIb und FId. Falsifikator: Falls die neuen `call 0x9dee001`-Stellen nur eine
Konstante (ohne MSR-Abhängigkeit) wären, entfiele die Frequenz-These; die `rdmsr`-Sequenz
auf `0xC0010064` ist jedoch byte-belegt.

**Konsequenz für K-Kandidaten:** eigener Beobachtungspunkt (kein K1–K10-Duplikat); kein
Korrektur-Bedarf, da reine Vendor-Verhaltensänderung. Für L2/L3-Edits im DXE/PEI irrelevant.
