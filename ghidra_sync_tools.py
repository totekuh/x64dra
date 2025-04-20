from ghidra_bridge import GhidraBridge
from time import sleep


class GhidraSyncManager:
    def __init__(self):
        self.current_addr = None
        self.bridge = None

        self.VALID_COLORS = {
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

    def _validate_color(self, color: str):
        if color not in self.VALID_COLORS:
            print("[!] Invalid color.")
            print("Valid colores are:")
            for color in self.VALID_COLORS:
                print(color)
            exit(1)

    def _execute_in_transaction(self, statement: str, transaction_name: str):
        return self.bridge.remote_exec(f"""
tx = currentProgram.startTransaction("{transaction_name}")
try:
{statement}
finally:
    currentProgram.endTransaction(tx, True)
""")

    def connect(self):
        print("[*] Connecting to GhidraBridge...")
        self.bridge = GhidraBridge()  # no namespace injection
        print("[+] Connected.")

    def get_functions(self):
        result = self.bridge.remote_eval(
            "[ (f.getName(), str(f.getEntryPoint())) "
            "for f in currentProgram.getFunctionManager().getFunctions(True) ]"
        )
        print(f"[*] {len(result)} functions in the current binary:")
        functions = {}
        for name, addr in result:
            functions[name] = addr
        return functions

    def highlight_instruction(self, addr_hex):
        self._execute_in_transaction(
            f"""
        addr = toAddr("{addr_hex}")
        goTo(addr)
    """,
            transaction_name="SyncAddress")
        print(f"[+] Jumped to {addr_hex}")

    def change_color_at_addr(self, addr_hex: str, color: str):
        self._validate_color(color=color)
        self._execute_in_transaction(
            f"""
        addr = toAddr("{addr_hex}")
        setBackgroundColor(addr, {color});
""",
            transaction_name="ChangeColorAtAddr")
        print(f"[+] Color changed to {color} at {addr_hex}")


if __name__ == "__main__":
    ghidra_sync_manager = GhidraSyncManager()
    ghidra_sync_manager.connect()
    ghidra_sync_manager.highlight_instruction(addr_hex='0x140003031')
    ghidra_sync_manager.change_color_at_addr(addr_hex="0x140003031",
                         color="Color.PINK")
