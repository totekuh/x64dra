from ghidra_bridge import GhidraBridge
from time import sleep

PLATE_COMMENT = "PLATE_COMMENT"
PRE_COMMENT = "PRE_COMMENT"

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
        self.VALID_COMMENT_TYPES = [
            PLATE_COMMENT,
            PRE_COMMENT
        ]

    def _validate_color(self, color: str):
        if color not in self.VALID_COLORS:
            print("[!] Invalid color.")
            print("Valid colores are:")
            for color in self.VALID_COLORS:
                print(color)
            exit(1)

    def _validate_comment_type(self, comment_type: str):
        if comment_type not in self.VALID_COMMENT_TYPES:
            print("[!] Invalid comment type.")
            print("Valid comment types are:")
            for comment_type in self.VALID_COMMENT_TYPES:
                print(comment_type)
            exit(1)

    def _execute_in_transaction(self, statement: str, transaction_name: str):
        # API docs
        # https://ghidra.re/ghidra_docs/api/index.html
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
        from java.awt import Color
        addr = toAddr("{addr_hex}")
        setBackgroundColor(addr, {color});
""",
            transaction_name="ChangeColorAtAddr")
        print(f"[+] Color changed to {color} at {addr_hex}")
    def add_comment_at_addr(self, addr_hex: str, comment: str, comment_type: str):
        self._validate_comment_type(comment_type)
        self._execute_in_transaction(
            f"""
        addr = toAddr({addr_hex})
        listing = currentProgram.getListing()
        codeUnit = listing.getCodeUnitAt(addr)
        codeUnit.setComment(codeUnit.{comment_type}, "{comment}")
""",
            transaction_name="AddCommentToAddr")
        print(f"[+] Comment ({comment}) added at {addr_hex}")
    def delete_comment_at_addr(self, addr_hex: str, comment_type: str):
        self._validate_comment_type(comment_type)
        self._execute_in_transaction(
            f"""
        addr = toAddr({addr_hex})
        listing = currentProgram.getListing()
        codeUnit = listing.getCodeUnitAt(addr)
        codeUnit.setComment(codeUnit.{comment_type}, "")
""",
            transaction_name="DeleteCommentAtAddr")
        print(f"[+] Comment deleted at {addr_hex}")

    def set_base_address(self, addr_hex: str):
        self._execute_in_transaction(
            f"""
        addr = toAddr({addr_hex})
        currentProgram.setImageBase(addr, True)
""",
            transaction_name="SetBaseAddr")
        print(f"[+] Base address set as {addr_hex}")

# if __name__ == "__main__":
#     ghidra_sync_manager = GhidraSyncManager()
#     ghidra_sync_manager.connect()
    # ghidra_sync_manager.set_base_address(addr_hex="0x0000000140000000")
#     ghidra_sync_manager.highlight_instruction(addr_hex='0x140001563')
#     ghidra_sync_manager.change_color_at_addr(addr_hex="0x140001563", color="Color.PINK")
#     ghidra_sync_manager.add_comment_at_addr(addr_hex="0x140001563",
#                                             comment="w00t",
#                                             comment_type=PRE_COMMENT)
#     sleep(2)
#     ghidra_sync_manager.delete_comment_at_addr(addr_hex="0x140001563", comment_type=PRE_COMMENT)
