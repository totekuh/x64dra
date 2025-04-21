# Ghidra ↔ x64dbg Sync Tool

A Python-based tool to synchronize **Ghidra** and **x64dbg/x32dbg** with minimal setup.

## Overview

This tool allows users to:
- Track the current instruction pointer from x64dbg inside Ghidra in real time
- Automatically rebase loaded modules in Ghidra to match x64dbg
- Export function symbols from Ghidra to x64dbg for clearer labeling and analysis

---

## Installation

Install the package and download Python dependencies:

```bash
git clone https://github.com/totekuh/x64dra
pip3 install .
```

For running this package, you'll need to configure `ghidra-bridge` and `LyScript`:

- https://github.com/justfoxing/ghidra_bridge
- http://lyscript.lyshark.com/

### ghidra-bridge

Install the server scripts into a directory that's part of Ghidra’s script path (e.g. `~/ghidra_scripts`). 

Note that you can add script directories in Ghidra via the Script Manager (click the three-line menu icon next to the red "+" button).

```bash
python3 -m ghidra_bridge.install_server C:\Users\<YourUsername>\ghidra_scripts
````

In Ghidra's Script Manager, select the `Bridge` folder, then check the `In Tool` box next to `ghidra_bridge_server_background.py` and `ghidra_bridge_server_shutdown.py`. 

This makes them accessible from `Tools → Ghidra Bridge` in the menu.

### LyScript

Download the LyScript plugin (or use the local copy in `lib/LyScript.zip`, SHA256 hash: 4a616b8d6d615847317ca5a696015dadfcffbb8628ecd999aaaaf3abbd32d71e) - http://lyscript.lyshark.com/LyScript.zip

Inside, you'll find `x32` and `x64` folders—pick the right one for your x64dbg debugger:

#### 32-bit

Extract the following files:
- `LyScript.zip\LyScript\1.1.0\x32\LyScript`
- `LyScript.zip\LyScript\1.1.0\x32\LyScript.dp32`

to the following folder:
- `x64dbg\release\x32\plugins\`

#### 64-bit

Extract the following files:
- `LyScript.zip\LyScript\1.1.0\x64\LyScript`
- `LyScript.zip\LyScript\1.1.0\x64\LyScript.dp64`

into the following folder:
- `x64dbg\release\x64\plugins\`

## Usage


### 1. Open Targets in Ghidra and x64dbg

- Load your binary in **Ghidra**.
- Load the same binary in **x64dbg** (x32dbg or x64dbg depending on architecture).

### 2. Start the Ghidra Bridge Server

In Ghidra, click on `Tools` -> `Ghidra Bridge` -> `Run in Background` to start the bridge server.

### 3. Run the Sync Tool

Now that both tools are prepped, run the sync tool from terminal:

```bash
x64dra --sync
```

Rebase loaded Ghidra modules to match x64dbg:

```bash
x64dra --rebase
```

Export function symbols from Ghidra to x64dbg

```bash
x64dra --ghidra-export-symbols
```

Print help:
```bash
x64dra --help
```

