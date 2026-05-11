# tok/ — Lightweight ragel-based tokenizers

Produces the same tag classification as ast/ tree-sitter parsers
(D=comment, G=string, L=number, R=keyword, P=punct, H=preproc, S=default)
but without the tree-sitter dependency.

## Core headers

| Header  | Purpose |
|---------|---------|
| TOK.h   | Common callback typedef `TOKcb`, dispatch API `TOKLexer()`, `TOKSplitText()` |
| BRCT.h  | Bracket matching and region detection on tokenized files |
| DEF.h   | Mark symbol definitions (S→N) via enrichment + NFA patterns, see [DEF.md](DEF.md) |
| HUNK.h  | Hunk TLV wire format (`HUNKu8sFeed`/`Drain`) + plain ASCII renderer (`HUNKu8sFeedText`), `HUNKu32sClip`, `HUNKu32bTokenize`, `HUNKu8sMakeURI`, `HUNKcb` |
| HOME.h  | Workspace finder + branch-sharding scaffolding: `HOMEFind` walks up to the nearest `.dogs` directory, `HOMEResolveSibling` finds tools next to the running binary, `HOMEOpenBranch`/`HOMEWriteBranch`/`HOMEBranchVisible` track the process-wide open-branch stack (slot 0 = writable, frozen at first rw open). Branch paths canonicalised via `dog/DPATH` helpers `DPATHBranchNormFeed`/`DPATHBranchAncestor`. |
| ULOG.h  | Append-only `<ts>\t<verb>\t<uri>\n` event log + persistent `wh128` sidecar index (`<dir>/.<base>.idx`). Index entries pack ts (60b key) and offset (40b) + verb-hash (20b prefilter) (val); tail sentinel records `(log_mtime, log_size)` — on Open, sidecar is trusted as-is when both match `fstat`, rebuilt on any mismatch. RO+missing sidecar quietly falls back to anonymous mmap. |
| WHIFF.h | `wh64` packed words (off40 \| id20 \| type4) and `wh128` (key, val) pairs. Used by ULOG idx, keeper LSM index, graf entries. SHA-1 hashlet helpers (40-bit / 60-bit). |

## Tag mapping

| Tag | Meaning | Color |
|-----|---------|-------|
| D   | Comment | gray  |
| G   | String  | green |
| L   | Number  | cyan  |
| H   | Preproc/annotation/pragma | pink |
| R   | Keyword | red   |
| P   | Punctuation | gray |
| S   | Default (identifier, whitespace) | default |
| N   | Defined name (from DEF pass) | — |
| C   | Function call (from DEF pass) | — |
| F   | Filename or path | #490d49 |

## Language tokenizers

| Header  | Language | Extensions |
|---------|----------|------------|
| CT.h    | C | c h |
| CPPT.h  | C++ | cpp cc cxx hpp hh hxx |
| GOT.h   | Go | go |
| PYT.h   | Python | py |
| JST.h   | JavaScript | js jsx mjs |
| TST.h   | TypeScript | ts tsx |
| RST.h   | Rust | rs |
| JAT.h   | Java | java |
| KTT.h   | Kotlin | kt kts |
| SCLT.h  | Scala | scala sc |
| CST.h   | C# | cs |
| FSHT.h  | F# | fs fsi fsx |
| SWFT.h  | Swift | swift |
| DARTT.h | Dart | dart |
| DT.h    | D | d |
| ZIGT.h  | Zig | zig |
| HTMT.h  | HTML | html htm |
| CSST.h  | CSS | css |
| SCSST.h | SCSS | scss |
| JSONT.h | JSON | json |
| YMLT.h  | YAML | yml yaml |
| TOMLT.h | TOML | toml |
| SHT.h   | Bash | sh bash |
| RBT.h   | Ruby | rb |
| LUAT.h  | Lua | lua |
| PRLT.h  | Perl | pl pm |
| RT.h    | R | r R |
| ELXT.h  | Elixir | ex exs |
| ERLT.h  | Erlang | erl hrl |
| HST.h   | Haskell | hs |
| MLT.h   | OCaml | ml mli |
| JLT.h   | Julia | jl |
| NIMT.h  | Nim | nim nims |
| PHPT.h  | PHP | php |
| CLJT.h  | Clojure | clj cljs cljc edn |
| NIXT.h  | Nix | nix |
| SQLT.h  | SQL | sql |
| GQLT.h  | GraphQL | graphql gql |
| PRTT.h  | Protobuf | proto |
| HCLT.h  | HCL/Terraform | hcl tf |
| LAXT.h  | LaTeX | tex sty cls |
| VIMT.h  | VimL | vim |
| CMKT.h  | CMake | cmake |
| DKFT.h  | Dockerfile | dockerfile |
| MAKT.h  | Makefile | mk |
| FORT.h  | Fortran | f90 f95 f03 f08 |
| GLST.h  | GLSL | glsl vert frag geom comp |
| GLMT.h  | Gleam | gleam |
| ODNT.h  | Odin | odin |
| PWST.h  | PowerShell | ps1 psm1 psd1 |
| SOLT.h  | Solidity | sol |
| TYST.h  | Typst | typ |
| MDT.h   | Markdown (block+inline two-pass) | md markdown |
| AGDT.h  | Agda | agda |
| VERT.h  | Verilog | v sv |

## Regenerating

```sh
cd tok/
ragel -C XX.c.rl -o XX.rl.c -L
```

where XX is the module prefix (CT, GOT, PYT, JST, RST, etc).
