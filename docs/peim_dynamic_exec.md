# Dynamische PEIM-Ausführung — Qiling vs. Unicorn-Harness (P-6)

**Datum:** 2026-11-19 · **Ziel:** `SmBusPei` (PE32/`pei-i386`) dynamisch ausführen und
seine PEI-Service-Abhängigkeiten sichtbar machen.
**Artefakte:** `scratches/p4_SmBusPei_{FIb,FId}_o139.pe.bin` · Harness `scratches/unicorn_peim.py`.
**Umgebung:** Python 3.12 (micromamba `qiling312`), Unicorn 2.1.4, Capstone 5.0.9, pefile.

## Befund 1 — Qiling ist hier nicht nutzbar (A)

`qiling 1.4.6` bringt `ostype=QL_OS.UEFI` (Loader `QlLoaderPE_UEFI`, Profil `uefi.ql`), aber
`QlLoaderPE_UEFI.run()` bricht ab mit:

> `qlErrorArch: Only 64-bit modules are supported at the moment`

Das UEFI-OS-Modul ist **DXE-orientiert** (DXE/SMM-Service-Tabellen, `gST`) und **64-bit-only**;
unsere PEIMs sind PE32. Qiling scheidet damit für die PEI-Module aus.

## Befund 2 — eigener Unicorn-Harness läuft (A)

`scratches/unicorn_peim.py`: lädt das PE32 an seiner `ImageBase`, installiert eine
**loggende Fake-`EFI_PEI_SERVICES`-Tabelle** (128 Slots, je ein distinkter `mov eax,0;ret`-Stub),
ruft den Entry mit `(Handle=0, &pPS)` und loggt jeden Service-Slot-Aufruf.

Wichtig: `pefile.SectionStructure.get_data()` liefert für dieses **synthetische** TE→PE32
falsche Bytes (MZ-Header statt Sektion); der Harness liest Sektionen daher direkt über
`PointerToRawData`/`SizeOfRawData` aus der Rohdatei.

**Ergebnis FIb und FId (identisch am Entry):**

```
entry FIb 0x9decf28 / FId 0x9decfb0
  PEI service slot 19 (table+0x4c)   ... 4 Aufrufe
  FAULT: write @0x0  (eax=0)
```

Ablauf im Entry: `mov edx,[esp+8]` ⇒ `edx=pPS`; `mov eax,[edx]` ⇒ Tabelle;
`call [eax+0x4c]` mit `(This=pPS, size=0x58, &out)`; danach wird der Rückgabe-Pointer
bei `+0x3c/+0x44/+0x48/+0x50/...` mit Funktionszeigern gefüllt und ein zweites Mal
`(This, 0xa0, &out)` gerufen. Weil der Stub `eax=0` liefert und den Out-Parameter
nicht beschreibt, faultet `mov [eax], …`.

## Deutung (B)

`table+0x4c` verhält sich wie ein **Allokations-/Puffer-Service** (Größe + Out-Pointer,
Rückgabe-Pointer wird danach als Struct beschrieben) — konsistent mit einer **AMI-PEI-
Services-Tabelle** (nicht die Standard-`PiPeiCis`-Reihenfolge). FIb und FId rufen ihn am
Entry gleich auf; das neue FId-Timing-Subsystem (`findings/smbuspei_fib_vs_fid.md`) liegt
tiefer und wird erst nach Auflösung dieses Service erreicht.

## Nächster Schritt

Den `+0x4c`-Service im Harness implementieren (Out-Parameter auf einen nullinitialisierten
Scratch-Puffer zeigen lassen, `eax=0` zurück) und iterativ den nächsten Service loggen, bis
der Modul-Dispatch (PPI-Install, SMBus-Zugriff) sichtbar wird. Alternativ `efi_dxe_emulator`
(gdbinit, Unicorn, 32-bit-fähig) als fertige Basis prüfen.

## Update — Entry vollständig ausgeführt, SMBus erreicht (A)

Mit implementiertem Allokator für `table+0x4c` (Bump-Allocator; `(This, size, *out)` ⇒
`*out = ptr`) läuft der **Entry beider Module vollständig**:

- **4× Registrierungsrunde:** Alloc `0x58/0x58/0xa0/0xa0` (Slot 19) → **PPI-Install**
  (Slot 8 = `table+0x20`, Descriptor @`0x9dee230`) → Slot 9 (`table+0x24`) → Slot 6 (`table+0x18`).
- Danach Zugriff auf **AMD-FCH-SMBus-MMIO `0xFED80304`** (echte HW-Region).
- Entry **kehrt sauber zurück** (ret an den Aufrufer).
- **FIb == FId** (identisch): 470 Instruktionen, 40 PEI-Calls, Histogramm `{6:8, 8:8, 9:8, 19:16}`,
  identische Allokationen. ⇒ Das FId-Timing-Subsystem wird im Entry nicht berührt; es liegt tiefer.

Die Slot-Offsets (6/8/9/19) passen **nicht** zur Standard-`PiPeiCis`-Reihenfolge (dort wäre
0x04 = InstallPpi, 0x20 wäre `CreateHob` …) → konsistent mit einer **AMI-extendierten
PEI-Services-Tabelle**. Die exakte Benennung der Slots 6/8/9 bleibt bis zur Tabellen-Revision offen.

**Ergebnis:** Der Unicorn-Harness ist ein funktionierender dynamischer PEIM-Runner; er zeigt die
Modul-Abhängigkeiten (4 PPI-Registrierungen, SMBus-MMIO) und reproduziert FIb/FId identisch.

## Update 2 — SMBus-Init-Trace (A)

Mit geloggten MMIO-Zugriffen auf das FCH-SMBus-Fenster (`0xFED80000`..`+0x2000`) zeigt der
Entry **4 identische Initialisierungsrunden** — FIb und FId byte-/ablaufgleich:

```
W 0xFED80304 = 0x00 ; W 0xFED80304 = 0x02
W 0xFED80302 = 0x00 ; W 0xFED80302 = 0x01
W 0xFED80300 = 0x00 ; W 0xFED80300 = 0x10      (× 4 Runden)
```

Es treten **keine Reads** im Entry auf: der PEIM *initialisiert* nur den FCH-SMBus
(Status-Bits löschen, Enable setzen). Die eigentlichen SMBus-Transaktionen (SPD/Temperatur)
laufen später, wenn die PEI-Core die registrierten PPIs aufruft — nicht im Entry. Der
FId-Timing-Unterschied (`rdtsc`-Delay, `findings/smbuspei_fib_vs_fid.md`) wird im Entry
nicht erreicht, weil er erst in den PPI-Handlern greift.

## Update 3 — SMBus-PPI-Handler ausgeführt: `Execute` → `EFI_SUCCESS` (A)

Der Harness kann nach dem Entry den **installierten SMBus-PPI-Handler aufrufen**
(`--exec`). Damit ist die SMBus-Transaktion nicht mehr nur statisch, sondern dynamisch
belegt.

### PPI-Interface (dynamisch gefunden)

Das beim Entry installierte SMBus-PPI ist ein **0x58-Byte-Alloc** mit einer
Funktionstabelle aus 4 In-Image-Codepointern. Für FId (`This=0x90001060`):

| Offset | FId | FIb | Rolle |
|-------:|-----|-----|-------|
| +0x00 | `0x9ded436` | `0x9ded3ae` | `Execute` |
| +0x04 | `0x9ded45b` | `0x9ded3d3` | `ArpDevice` |
| +0x08 | `0x9ded47c` | `0x9ded3f4` | `GetArpMap` |
| +0x0c | `0x9ded499` | `0x9ded…` | `Notify` (= `EFI_UNSUPPORTED` `0x80000003`) |

GUID im Struct: `55c37192-87d6-4aa4-9f11-2e881f80d672`. Der Harness wählt das Interface
**dynamisch** (erstes 0x58-Alloc, dessen erste 4 Dwords gültige In-Image-Pointer sind), weil
FIb/FId unterschiedliche Image-Basen und Handler-Adressen haben.

### Aufruf

`Execute(This, SlaveAddress=0x50, Command=0x00, Operation=EfiSmbusReadByte(4),
PecCheck=0, Length=&1, Buffer)` — **Standard-Reihenfolge** des
`EFI_PEI_SMBUS_PPI_EXECUTE_OPERATION` (`This, SlaveAddress, Command, Operation, PecCheck,
Length, Buffer`). Eine frühere Variante mit vertauschten Argumenten schrieb `0x09` statt
`0xA1` ins Adressregister (siehe unten).

**Ergebnis FId:**

```
SMBus PPI This=0x90001060 Execute=0x9ded436
Execute → eax=0x00000000 (EFI_SUCCESS), sauberer Return, 92472 Instruktionen
out buffer: pointer=0x90200040 len=1 bytes=12
```

Beim ersten Lauf hing `Execute` in drei verschiedenen Poll-Schleifen; Ursachen + Fixes:

| Blocker | Ursache | Harness-Fix |
|---|---|---|
| rdtsc-Delay | Unicorn 2.1.4 kann `RDTSC` nicht per `UC_HOOK_INSN` hooken | Capstone-Scan → Code-Hook, `EIP+=2`, synthetischer TSC |
| P-State-Erkennung | `rdmsr 0xC0010064+i`, Test EDX-Bit31; `uc.msr_write` wirkt nicht auf `rdmsr` | Capstone-Scan → Code-Hook liefert gültigen P-State-MSR (`bit63|DfsId<<8|Fid`) |
| Endlos-Delay | RDTSC-Schleife mit großem Ziel | Delay-Funktion (Entry = `min(rdtsc)-1`) per Hook sofort zurückkehren |
| SMBus-Status | `in al,dx` auf Status-Reg. 0, wartet auf **HostBusy (Bit0)=0**; Unicorn hat kein IO-Backend | `IN`/`OUT`-Hooks: `0x0B00/01/02` ⇒ `0x00` (idle), `0x0B04/05` ⇒ Sample-Byte, sonst `0xFF` |

### Beobachtete IO-Sequenz (FId, ISA-IO-Basis `0x0B00`)

Der SMBus-Controller ist **IO-decoded bei `0x0B00`** (der Entry nutzt daneben das
MMIO-Fenster `0xFED80300`). Register: `0x0B00` Status, `0x0B01` Control, `0x0B02`
Host-Control, `0x0B03` Host-Command, `0x0B04` Host-Adresse, `0x0B05` Host-Data 0.

```
; --- Controller-Init / Bus-free (0x9dedafb) ---
R 0x0B08                               ; Bus-free-Status
W 0x0B08 = 0xFF
R 0x00ED ; R 0x00ED                    ; AMD-Standard-Delay (Port 0xED)
R 0x0B08                               ; Bit4 (0x10) gesetzt → Bus frei
W 0x0B00 = 0x1F                        ; Status-Bits löschen
R 0x0B00 = 0x00                        ; HostBusy=0
W 0x0B01 = 0x3F                        ; Control/Enable

; --- ReadByte-Transaktion (Slave 0x50, Command 0x00) ---
R 0x0B02 = 0x00
W 0x0B04 = 0xA1                        ; SlaveAddress 0x50 << 1 | Read
W 0x0B03 = 0x00                        ; Command
W 0x0B02 = 0x48                        ; Host-Control: Start + ReadByte-Protokoll
R 0x0B05 = 0x12                        ; Host-Data 0  → Buffer[0]
W 0x0B02 = 0x00                        ; Control zurücksetzen
```

Damit ist die Transaktion **vollständig**: Adresse `0xA1`, Command `0x00`, gelesenes Byte
`0x12`, das im Caller-Buffer landet. Die Delay-Schleife nutzt `RDTSC` (nur FId:
`findings/smbuspei_fib_vs_fid.md`), die Frequenz kommt aus den P-State-MSRs — beides ist
oben emuliert.

### FIb-Status (offen)

FIb hat vier 0x58-PPI-Kandidaten (`PEIM_PPI_INDEX=0..3`):

| Index | `This` | `Execute` | Ergebnis |
|------:|--------|-----------|----------|
| 0 | `0x90001060` | `0x9ded3ae` | Fault `0x9ded4a5` (Null-Vtable) nach 261 Instr. |
| 1 | `0x90001260` | `0x9ded3ae` | Fault `0x9ded4a5` nach 19 099 Instr. |
| 2 | `0x90001460` | `0x9ded4ac` | sauberer Return, `eax=0x80000002` (`EFI_INVALID_PARAMETER`), 76 Instr. |
| 3 | `0x90001660` | `0x9ded4ac` | identisch zu Index 2 |

**Ursache FIb (0/1):** FIb nutzt im Wartepfad einen **Vtable-Dispatch**
(`mov eax,[edi]; call [eax+4]` → ArpDevice-Wrapper → `[This-8]`=0), während FId an
derselben Stelle direkt `0x9dee001` (Delay/Frequenz) ruft. Die Vtable-Back-Pointer
(`[This-8]`) wird in FIb offenbar über einen PEI-Service initialisiert, den unser Fake
nicht bedient. **Index 2/3** ist eine zweite PPI-Instanz mit anderem Protokoll und weist
unsere Parameter mit `EFI_INVALID_PARAMETER` ab.

Nächster Schritt: den FIb-Wartepfad statisch nachvollziehen (wer setzt `[This-8]`, welcher
PEI-Service) und den Kontext vor `Execute` entsprechend aufbauen — oder den FIb-Index 0/1
mit einem vorinitialisierten Vtable-Back-Pointer testen.

### Einordnung

- **FId:** SMBus-PPI `Execute` ist end-to-end emuliert (Erfolgspfad, vollständiger IO-Trace,
  Datenrückgabe in den Caller-Buffer) → **A**.
- Der **Dateninhalt** ist als Sample-Byte (`0x12`) modelliert; für echte SPD-Daten muss der
  `0x0B05`-Read mit dem DIMM-Inhalt gespeist werden. Adresse (`0xA1`) und Command (`0x00`)
  werden korrekt aus den PPI-Argumenten gebildet.
- Reproduktion:
  `/home/julian/micromamba/envs/qiling312/bin/python scratches/unicorn_peim.py scratches/p4_SmBusPei_FId_o139.pe.bin 200000 --exec`


