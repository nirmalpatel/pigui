# Building Snort for PIGUI

PIGUI consumes Snort as an external binary. The build must provide the
inspectors, loggers, and connector that PIGUI's generated configuration uses,
and ideally shell/control-socket support.

## What PIGUI needs from Snort

| Capability | Why | Check |
|---|---|---|
| `alert_json` logger | Alert ingestion | `snort --help-modules \| grep alert_json` |
| `extractor` inspector | Connection and protocol telemetry | `snort --help-modules \| grep extractor` |
| `file_connector` | Writes extractor JSONL to disk | `snort --help-modules \| grep file_connector` |
| `dns` with `publish_response` | DNS answer ingestion | `snort --help-modules \| grep dns` |
| `stream` | Flow tracking | `snort --help-modules \| grep stream` |
| pcap/BPF DAQ | Passive live capture | see DAQ modules below |
| `--enable-shell` | Control socket (preferred, not yet used by PIGUI) | `snort --help-options \| grep control-socket` |

PIGUI also needs a usable Snort `lua/` tree containing `snort.lua` and
`snort_defaults.lua`. Configuration generation copies from it; the parent tree
is never edited.

## Verified macOS build

Verified on macOS 15.5 arm64 with Snort 3.12.4.0. The resulting binary is
Mach-O arm64 and reports:

```text
Version 3.12.4.0
DAQ 3.0.28.0
Hyperscan 5.4.13
Jemalloc 5.4.0
libpcap 1.11.0
LuaJIT 2.1.1793383622
LZMA 5.8.1
OpenSSL 3.6.4
PCRE2 10.47
zlib 1.2.12
```

Build settings used: `RelWithDebInfo`, prefix `/usr/local/snort`,
`ENABLE_SHELL=ON`, `ENABLE_JEMALLOC=ON`, static DAQ modules
`bpf divert dump fst pcap savefile trace`.

### Homebrew dependencies

```bash
brew install cmake flex bison pkgconf \
  libpcap libdnet daq luajit hwloc openssl@3 pcre2 vectorscan jemalloc xz
```

`bison` is included for completeness; the verified host used the system bison.
`vectorscan` provides Hyperscan-compatible headers and libraries.

### Configure and build

Run from the Snort repository root, not from `pigui/`:

```bash
export HOMEBREW_PREFIX="$(brew --prefix)"
export PATH="$HOMEBREW_PREFIX/opt/flex/bin:$PATH"
export PKG_CONFIG_PATH="$HOMEBREW_PREFIX/opt/libpcap/lib/pkgconfig:$HOMEBREW_PREFIX/opt/libdnet/lib/pkgconfig:$HOMEBREW_PREFIX/opt/daq/lib/pkgconfig:$HOMEBREW_PREFIX/opt/luajit/lib/pkgconfig:$HOMEBREW_PREFIX/opt/hwloc/lib/pkgconfig:$HOMEBREW_PREFIX/opt/openssl@3/lib/pkgconfig:$HOMEBREW_PREFIX/opt/pcre2/lib/pkgconfig:$HOMEBREW_PREFIX/opt/vectorscan/lib/pkgconfig:$HOMEBREW_PREFIX/opt/jemalloc/lib/pkgconfig:$HOMEBREW_PREFIX/opt/xz/lib/pkgconfig"
export CMAKE_PREFIX_PATH="$HOMEBREW_PREFIX/opt/libpcap:$HOMEBREW_PREFIX/opt/libdnet:$HOMEBREW_PREFIX/opt/daq:$HOMEBREW_PREFIX/opt/luajit:$HOMEBREW_PREFIX/opt/hwloc:$HOMEBREW_PREFIX/opt/openssl@3:$HOMEBREW_PREFIX/opt/pcre2:$HOMEBREW_PREFIX/opt/vectorscan:$HOMEBREW_PREFIX/opt/jemalloc:$HOMEBREW_PREFIX/opt/xz"

./configure_cmake.sh \
  --prefix=/usr/local/snort \
  --enable-shell \
  --enable-jemalloc \
  --disable-docs \
  --with-openssl="$HOMEBREW_PREFIX/opt/openssl@3" \
  --with-flex-prefix="$HOMEBREW_PREFIX/opt/flex" \
  --with-pcap-includes="$HOMEBREW_PREFIX/opt/libpcap/include" \
  --with-pcap-libraries="$HOMEBREW_PREFIX/opt/libpcap/lib" \
  --with-daq-includes="$HOMEBREW_PREFIX/opt/daq/include" \
  --with-daq-libraries="$HOMEBREW_PREFIX/opt/daq/lib" \
  --with-dnet-includes="$HOMEBREW_PREFIX/opt/libdnet/include" \
  --with-dnet-libraries="$HOMEBREW_PREFIX/opt/libdnet/lib" \
  --with-luajit-includes="$HOMEBREW_PREFIX/opt/luajit/include/luajit-2.1" \
  --with-luajit-libraries="$HOMEBREW_PREFIX/opt/luajit/lib" \
  --with-pcre2-includes="$HOMEBREW_PREFIX/opt/pcre2/include" \
  --with-pcre2-libraries="$HOMEBREW_PREFIX/opt/pcre2/lib" \
  --with-hyperscan-includes="$HOMEBREW_PREFIX/opt/vectorscan/include" \
  --with-hyperscan-libraries="$HOMEBREW_PREFIX/opt/vectorscan/lib"

# Homebrew's jemalloc and xz headers are outside the default include search.
cmake -S . -B build \
  -DCMAKE_CXX_FLAGS="-I$HOMEBREW_PREFIX/opt/jemalloc/include -I$HOMEBREW_PREFIX/opt/xz/include" \
  -DCMAKE_C_FLAGS="-I$HOMEBREW_PREFIX/opt/jemalloc/include -I$HOMEBREW_PREFIX/opt/xz/include"

cd build
make -j"$(sysctl -n hw.ncpu)"
./src/snort -V
./src/snort -c ../lua/snort.lua -T
```

Expected validation ends with a success message. If it does not, fix the Snort
build before debugging PIGUI.

### Point PIGUI at the binary

The default is `../build/src/snort` relative to `pigui/`, which resolves to the
in-tree build above. Override it when needed:

```bash
export PIGUI_SNORT_BIN=/absolute/path/to/snort
./scripts/probe-snort.sh
```

PIGUI resolves Snort in this order:

1. `PIGUI_SNORT_BIN`
2. `../build/src/snort`
3. `../install/bin/snort`
4. `/usr/local/snort/bin/snort`
5. `snort` in `PATH`
6. Homebrew locations, with a warning that the control socket may be missing

PIGUI does not install Snort system-wide during development.

## macOS variants

### Intel Macs

Build natively. Homebrew uses `/usr/local` instead of `/opt/homebrew`; the same
commands work with `HOMEBREW_PREFIX` expanded to the Intel prefix.

### Universal binary

```bash
cmake -S . -B build \
  -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
  -DCMAKE_CXX_FLAGS="-I$HOMEBREW_PREFIX/opt/jemalloc/include -I$HOMEBREW_PREFIX/opt/xz/include" \
  -DCMAKE_C_FLAGS="-I$HOMEBREW_PREFIX/opt/jemalloc/include -I$HOMEBREW_PREFIX/opt/xz/include"
```

Every linked dependency must also be universal. Homebrew bottles are built per
architecture, so this usually requires universal builds of libpcap, DAQ,
LuaJIT, OpenSSL, Hyperscan, and the rest. Building on each target architecture
is simpler and is the recommended release approach.

## Linux

Status: **unverified** by this project. Treat this section as a starting point,
not a tested recipe.

PIGUI's Linux plan is passive Snort plus a firewall backend (`ufw` first,
then `nftables`/`ipset`). Inline Snort is optional and not the default.

Typical Debian/Ubuntu packages:

```bash
sudo apt install build-essential cmake pkg-config flex bison \
  libpcap-dev libdumbnet-dev libluajit-5.1-dev libhwloc-dev \
  libssl-dev libpcre2-dev libhyperscan-dev zlib1g-dev liblzma-dev \
  libjemalloc-dev
```

DAQ is often built from source and installed separately. Build Snort with
`--enable-shell`, the appropriate `--with-*` paths, and `--disable-docs`.
Then:

```bash
./src/snort -V
./src/snort -c ../lua/snort.lua -T
./src/snort --help-modules | grep -E 'alert_json|extractor|file_connector'
```

Adapt `PIGUI_SNORT_BIN`, `PIGUI_SNORT_CONFIG`, and `PIGUI_SNORT_LUA_PATH` to
the Linux install layout. PIGUI's current collector is macOS-only
(`nettop`/`ps`), so live process attribution will not work on Linux until a
Linux collector exists.

## Windows

Status: **not supported**. Native Windows Snort is not a first-class build
target in this tree.

Recommended paths:

- WSL2 running the Linux build and Linux collector plan.
- A Linux container or VM.
- A remote Linux sensor feeding PIGUI later.

Native Windows would require a separate research effort covering the Snort C++
toolchain, vcpkg or equivalent dependencies, DAQ and Npcap support, a Windows
collector (`GetExtendedTcpTable`/ETW), and Windows Defender Firewall or WFP.
Do not assume the macOS or Linux instructions carry over.

## Cross-compilation

Do not cross-compile Snort for PIGUI release use. Its dependency graph
(libpcap, DAQ, LuaJIT, OpenSSL, Hyperscan) is large and platform-specific.
Build on the target OS/architecture or in a matching VM/container.

## Troubleshooting the build

- `extractor` or `alert_json` missing: the corresponding inspector/logger was
  disabled or the build did not include the library. Check `--help-modules`.
- `control socket unavailable`: Snort was not built with `--enable-shell`.
- Validation fails on `snort_defaults.lua`: PIGUI needs both `snort.lua` and
  `snort_defaults.lua` in the same directory.
- Link errors for jemalloc or xz on macOS: the include flags above are
  required.
- Hyperscan not found: Homebrew ships it as `vectorscan`; point
  `--with-hyperscan-*` at the `vectorscan` prefix.
