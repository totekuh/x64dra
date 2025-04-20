from ghidra_bridge import GhidraBridge

def connect():
    print("[*] Connecting to GhidraBridge...")
    bridge = GhidraBridge()  # no namespace injection
    print("[+] Connected.")
    return bridge

def get_functions(bridge):
    result = bridge.remote_eval(
        "[ (f.getName(), str(f.getEntryPoint())) "
        "for f in currentProgram.getFunctionManager().getFunctions(True) ]"
    )
    print(f"[*] {len(result)} functions in the current binary:")
    functions = {}
    for name, addr in result:
        functions[name] = addr
    return functions

def highlight_instruction(bridge, addr_hex):
    script = f"""
tx = currentProgram.startTransaction("SyncHighlight")
try:
    addr = toAddr("{addr_hex}")
    goTo(addr)
    cu = currentProgram.getListing().getCodeUnitAt(addr)
    cu.setComment(cu.EOL_COMMENT, "⛓ Synced with debugger")
finally:
    currentProgram.endTransaction(tx, True)
"""
    bridge.remote_exec(script)
    print(f"[+] Jumped to {addr_hex} and tagged it.")



if __name__ == "__main__":
    bridge = connect()
    highlight_instruction(bridge=bridge, addr_hex='0x140001428')
