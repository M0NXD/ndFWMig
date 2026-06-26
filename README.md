# ndFWMig

A desktop firewall-configuration migration tool. Parse a configuration from one
firewall platform into a platform-agnostic model, inspect it, and regenerate it
for a different platform — all from a single GUI, with no cloud services and no
third-party runtime dependencies.

## Supported platforms

ndFWMig parses **and** generates every platform below, so any source → target
combination is possible:

| Platform | Format | Versions |
|----------|--------|----------|
| Cisco ASA | CLI | 7.x – 9.24 |
| Cisco FWSM | CLI | 2.3 – 4.1 |
| Cisco FTD | LINA CLI | 6.0 – 10.0 |
| Palo Alto PAN-OS | `set` commands | 8.0 – 12.1 |
| FortiGate FortiOS | CLI | 5.0 – 8.0 |

## Features

- **Any-to-any migration** — every platform has both a parser and a generator,
  built around a shared intermediate representation (IR).
- **Auto-detection** — paste or load a config and let ndFWMig identify the
  platform and version.
- **Statistics** — rule/object/NAT counts, protocol and zone distribution,
  logging coverage, any-any and shadowed-rule detection, and a complexity score.
- **Warnings & migration risks** — parse errors, parse warnings, and
  target-specific generation warnings are surfaced in one place.
- **Interface / zone mapping** — refactor interface and zone names for the
  target, including expanding a zone to several interfaces (or collapsing
  interfaces into a zone) when crossing between zone-based and interface-based
  platforms.
- **Syntax highlighting** for both the source and generated configs.
- **Copy or save** the generated configuration.

## Requirements

- Python 3.9+
- Tkinter (bundled with the standard CPython installer on Windows and macOS; on
  Debian/Ubuntu install `python3-tk`)

There are **no third-party runtime dependencies** — ndFWMig uses only the Python
standard library (`tkinter` for the GUI and `xml.etree.ElementTree` for PAN-OS
XML).

## Installation

```bash
git clone https://github.com/<your-org>/ndmig.git
cd ndmig
```

(Optional) create a virtual environment, then install the dev/test dependency:

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Unix:     source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

Launch the GUI from the project root:

```bash
python main.py
```

Then:

1. Choose the **source** platform/version (or click **Auto-detect** after
   loading a config).
2. **Browse...** to a config file, or paste one into the *Source Config* tab.
3. Click **Parse** — review the *Statistics* and *Warnings & Risks* tabs.
4. Choose the **target** platform/version. Optionally click **Map
   Interfaces...** to refactor interface/zone names.
5. Click **Generate**, then **Copy** or **Save...** the result.

## Project layout

```
main.py                  # entry point — launches the GUI
fwmig/
  models/common.py       # platform-agnostic intermediate representation (IR)
  parsers/               # one parser per platform -> IR
  generators/            # one generator per platform <- IR
  transform/             # interface/zone mapping and normalization
  statistics/            # config analysis, risks, complexity score
  util/                  # IP/netmask helpers
  gui/app.py             # Tkinter application
```

Every parser produces a `FirewallConfig` (the IR), and every generator consumes
one. Adding a new platform means writing a parser and/or generator against that
shared model — nothing else in the pipeline has to change.

## License

Released under the [MIT License](LICENSE).
