from ghidra_bridge import GhidraBridge
from time import sleep


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


def execute_in_transaction(bridge, statement: str, transaction_name: str):
    return bridge.remote_exec(f"""
tx = currentProgram.startTransaction("{transaction_name}")
try:
{statement}
finally:
    currentProgram.endTransaction(tx, True)
""")


def highlight_instruction(bridge, addr_hex):
    execute_in_transaction(bridge,
                           f"""
    addr = toAddr("{addr_hex}")
    goTo(addr)
""",
                           transaction_name="SyncAddress")
    print(f"[+] Jumped to {addr_hex} and tagged it.")


def change_color_at_addr(bridge, addr_hex, color):
    script = f"""
tx = currentProgram.startTransaction("SyncHighlight")

try:
    addr = toAddr("{addr_hex}")
    goTo(addr)
finally:
    currentProgram.endTransaction(tx, True)
"""
    bridge.remote_exec(script)
    print(f"[+] Jumped to {addr_hex} and tagged it.")


if __name__ == "__main__":
    bridge = connect()
    highlight_instruction(bridge=bridge, addr_hex='0x140002f2c')
    sleep(2)
    highlight_instruction(bridge=bridge, addr_hex='0x140002f36')
    sleep(2)
    highlight_instruction(bridge=bridge, addr_hex='0x140003031')
