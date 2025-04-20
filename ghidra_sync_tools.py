from ghidra_bridge import GhidraBridge
from time import sleep

VALID_COLORS = {
    "Color.BLACK",
    "Color.BLUE",
    "Color.CYAN",
    "Color.DARK_GRAY",
    "Color.GRAY",
    "Color.GREEN",
    "Color.LIGHT_GRAY",
    "Color.MAGENTA",
    "Color.ORANGE",
    "Color.PINK",
    "Color.RED",
    "Color.WHITE",
    "Color.YELLOW"
}

def validate_color(color: str):
    if color not in VALID_COLORS:
        print("[!] Invalid color.")
        print("Valid colores are:")
        for color in VALID_COLORS:
            print(color)
        exit(1)

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
    print(f"[+] Jumped to {addr_hex}")


def change_color_at_addr(bridge, addr_hex: str, color: str):
    validate_color(color=color)
    execute_in_transaction(bridge,
                           statement=f"""
    addr = toAddr("{addr_hex}")
    setBackgroundColor(addr, {color});
""",
                           transaction_name="ChangeColorAtAddr")
    print(f"[+] Color changed to {color} at {addr_hex}")


if __name__ == "__main__":
    bridge = connect()
    # highlight_instruction(bridge=bridge, addr_hex='0x140002f2c')
    # sleep(2)
    # highlight_instruction(bridge=bridge, addr_hex='0x140002f36')
    # sleep(2)
    highlight_instruction(bridge=bridge, addr_hex='0x140003031')
    change_color_at_addr(bridge, addr_hex="0x140003031",
                         color="Color.PINK")
