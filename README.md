
delta16
===

`delta16` is a simple delta encoding scheme (aka differential compression) 
which generates small patch files between related binary object files.
It understands 16-bit address relocation for patching compiled 65c02 assembly code.
For example imagine a 16K ROM image where we make a small change to the 
assembly source.  Much of the object code is the same, but many addresses shift slightly
causing many small changes throughout the file.  However those changes typically happen in
a way that we can encode effectively.

In the same spirit as Chromium's 
[Courgette](https://www.chromium.org/developers/design-documents/software-updates-courgette/) we reconstruct
the new binary image using the source image and a compact sequence of instructions in a very simple
machine code that understands simple relocation.
Our machine code has seven distinct instructions that conceptually edit the source to produce the target.
Each instruction is encoded as a single byte with zero or more argument bytes, and appends 0 to 63
bytes to the destination.
To reconstruct the target byte sequence we initialize two 16 bit offsets, `src=0` and `dst=0`,
and then follow the instructions. 
The `dst` offset increases monotonically but `src` can jump back and forth as we refer to different
regions within the source sequence.

The worst case encoding would simply ignore the source file and reproduce the destination
using a sequence of `INS_n` instructions, increasing the source size by 1/63 (+1.6%).  
However with a source file that's similar to our target we can often do much better.

| operation | opcode | arguments | action | src | dst |
| ---       | ---   |  ---    | --- | --- | --- |
| `END`   | `0000_0000` | - | Update complete, aka `RPL_0`| 0 | 0 |
| `RPLn`  | `000n_nnnn` | `v0` ... `vn` | Replace $n>0$ bytes from src<sup>1</sup>  | $+n$ | $+n$ |
| `RLOn`  | `001n_nnnn` | - | Relocate $n>0$ little endian offsets<sup>2</sup> | $+2n$ | $+2n$ |
| `CPY16` | `0100_0000` | `n16` | Copy $n_{16}$ bytes from src | $+n_{16}$ | $+n_{16}$ |
| `CPYn`  | `01nn_nnnn` | - | Copy $n>0$ bytes from src | $+n$ | $+n$ |
| | | | | | |
| `ADD16` | `1000_0000` | `n16 v0` ...  | Insert $n_{16}$ new bytes to dst | 0 | $+n_{16}$ |
| `ADDn`  | `10nn_nnnn` | `v0` ... `vn` | Insert $n$ new bytes to dst | 0 | $+n$ |
| `SKP16` | `1100_0000` | `n16` | Skip $n_{16}$ signed bytes of src<sup>3</sup> | $+n_{16}$ | 0 |
| `SKPn`  | `11nn_nnnn` | - | Skip $n$ bytes of src | $+n$ | 0 |

Notes:

1. Although `RPL` might seem unnecesssary given `ADD`,
by preserveing alignment between `src` and `dst`
it leads to more compact encoding and fewer relocation entries.

2. The `RLO` instruction copies one or more little endian offsets with relocation.
For each entry, interpret the next two bytes as a little endian address in the
`src` address space.  Remap that address using the first relocation table entry 
which includes it.  Emit the adjusted little-endian address.

3. Negative offsets are represented in the usual twos complement form, 
so that `src` + $n_{16}$ discarding carry gives the desired result.

To build the relocation table we make an initial pass through the instructions 
without emitting data.
The table tracks how contiguous ranges of source offsets map to destination offsets.  
Each entry is a triple `(src, delta, n)` which indicates that
source offsets `[src, src+n)` map to destination offsets `[src+delta, src+n+delta)`.
The inferred destination offset ranges are disjoint, but source offset ranges can overlap.

The table is constructed as follows:

1. Start with `src` = `dst` = 0.  
2. Initialize a relocation entry `(src, delta, ?)` where `delta` = `dst-src`.
3. Update `src` and `dst` for consecutive instructions that preserve `delta`,
  i.e. CPY, CHG and REL, stopping when `delta` changes, i.e. END, INS, DEL or SET.
4. Finalize the relocation entry with `n` = `src - src0`.
5. Update `src` and `dst` for consecutive instructions that change delta, i.e. END, INS, DEL or SET,
  stopping on CPY, CHG or REL.
6. Repeat to step 2.


Relocation
---

`src` will be loaded at `src_start`, `dst` will be loaded at `dst_start`

so relocation block `(dst_offset, src_offset, n)` corresponds to the address
mapping `(dst_offset+dst_start, src_offset+src_start, n)`.  

so an address `src_addr` becomes `dst_addr = src_addr + (dst_offset - src_offset) + (dst_start - src_start)`

either provide `dst_start` and `src_start` or (maybe) optimize over a bunch of candidate relocation pairs.
also need to provide those values as part of the patch file

delta16 patch format
---

A full patch blob contains a short header
followed by a zero-terminated byte sequence of delta instructions and arguments
followed by the [Fletcher-16](https://en.wikipedia.org/wiki/Fletcher%27s_checksum) 
of the decoded result.
Note that the instruction sequence bytes can contain null bytes,
but only a single null instruction, i.e. the final `0` indicating `END`.


| start | end | description |
| --- | --- | --- |
| 0  | 1 | magic number 0x16 0x0d |
| 2  | 3 | start offset for src |
| 4  | 5 | length of src (for checksum) |
| 6  | 7 | Fletcher16 checksum of src |
| 8  | 9 | start offset for dst |
| 10 | -4 | sequence of opcodes and arguments |
| $-3 | -3 | `0` terminator, aka END instruction |
| $-2 | -1 | Fletcher16 checksum of dst |

