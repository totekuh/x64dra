from ghidra_bridge import GhidraBridge

bridge = None

def connect():
    global bridge
    if bridge is None:
        print("[*] Connecting to GhidraBridge...")
        bridge = GhidraBridge(namespace=globals())
        print("[+] Connected to Ghidra.")
    else:
        print("[*] GhidraBridge already connected.")

def get_functions():
    if currentProgram is None:
        raise RuntimeError("[-] No program loaded in Ghidra.")

    func_mgr = currentProgram.getFunctionManager()
    functions = func_mgr.getFunctions(True)

    func_list = []
    for f in functions:
        func_list.append((f.getName(), str(f.getEntryPoint())))
    return func_list

def highlight_instruction(addr_hex):
    if currentProgram is None:
        raise RuntimeError("[-] No program loaded in Ghidra.")

    listing = currentProgram.getListing()
    addr = toAddr(addr_hex)
    code_unit = listing.getCodeUnitAt(addr)

    # Navigate disassembly view to this address
    goTo(addr)

    # Add a comment to simulate visual feedback (can be replaced with color/highlight)
    code_unit.setComment(code_unit.EOL_COMMENT, "⛓ Synced with debugger")

    print(f"[+] Jumped to {addr} and tagged it.")

# For test/dev mode
if __name__ == "__main__":
    connect()
    funcs = get_functions()
    for name, addr in funcs[:10]:
        print(f"{name} @ {addr}")

    # Example sync highlight
    highlight_instruction("0x401000")
