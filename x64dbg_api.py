from time import sleep

from ghidra_sync_tools import GhidraSyncManager

DEFAULT_DEBUGGER_IP = "127.0.0.1"
DEFAULT_DEBUGGER_PORT = 6589

X64_ARCH = 'x64'
X32_ARCH = 'x32'


def get_arguments():
    from argparse import ArgumentParser
    parser = ArgumentParser(description="x64dbg connector")
    parser.add_argument("--ip",
                        type=str,
                        default=DEFAULT_DEBUGGER_IP,
                        required=False,
                        help="IP address of the x64dbg API socket. "
                             f"Default is {DEFAULT_DEBUGGER_IP}.")
    parser.add_argument("--port",
                        type=int,
                        default=DEFAULT_DEBUGGER_PORT,
                        required=False,
                        help="Port number of the x64dbg API socket. "
                             f"Default is {DEFAULT_DEBUGGER_PORT}.")
    parser.add_argument("--arch",
                        type=str,
                        choices=[
                            X64_ARCH,
                            X32_ARCH
                        ],
                        default=X64_ARCH,
                        required=False,
                        help="Debugger architecture. "
                             f"Default is {X64_ARCH}.")
    parser.add_argument("--rebase",
                        action='store_true',
                        required=False,
                        help="Rebase base addresses of the matching modules. "
                             "This will instruct the script to fetch the base address of the currently "
                             "loaded module in the debugger and set it as the base address in Ghidra.")
    return parser.parse_args()


class DebuggerConnector:
    def __init__(self,
                 ip: str,
                 port: int,
                 arch: str):
        self.ip = ip
        self.port = port
        self.arch = arch
        if self.arch == X64_ARCH:
            from x64dbg import Debugger
        elif self.arch == X32_ARCH:
            from x32dbg import Debugger
        else:
            raise Exception(f"Invalid architecture provided: {self.arch}")
        self.dbg = Debugger(address=self.ip, port=self.port)

    def connect(self):
        if self.dbg.connect():
            print(f"[+] Connected to {self.arch}dbg")
        else:
            raise Exception(f"Failed to connect to the {self.arch}dbg API")

    def disconnect(self):
        self.dbg.close_connect()

    def get_main_module_base_addr(self):
        return self.dbg.get_main_module_base()

    def get_instruction_pointer(self):
        if self.arch == X32_ARCH:
            return self.dbg.get_eip()
        elif self.arch == X64_ARCH:
            return self.dbg.get_rip()
        else:
            return 0

    def get_loaded_modules(self):
        modules = self.dbg.get_module()
        result = {}
        if modules:
            for mod in modules:
                name = mod['Name'].lower()
                result[name] = {
                    "base": hex(mod['Base']),
                    "entry": hex(mod['Entry']),
                    "path": mod['Path'],
                    "size": mod['Size']
                }
        return result

    def find_module_by_address(self, addr: int):
        modules = self.get_loaded_modules()
        for name, mod in modules.items():
            base = int(mod["base"], 16)
            size = mod["size"]
            if base <= addr < base + size:
                return {
                    "module": name,
                    "base": hex(base),
                    "size": hex(size),
                    "path": mod["path"],
                    "offset": hex(addr - base)
                }
        return None


def sync_loaded_modules(debugger: DebuggerConnector, ghidra: GhidraSyncManager):
    print("[*] Checking for base address mismatches...")

    dbg_modules = debugger.get_loaded_modules()
    ghidra_files = ghidra.get_loaded_files()

    for ghidra_name, ghidra_base in ghidra_files.items():
        ghidra_name = ghidra_name.lower()
        if ghidra_name in dbg_modules:
            dbg_base = dbg_modules[ghidra_name]["base"]
            if dbg_base != ghidra_base:
                print(f"    -> Rebasing {ghidra_name}: {ghidra_base} → {dbg_base}")
                ghidra.set_base_address(file_name=ghidra_name, addr_hex=dbg_base)
            else:
                print(f"    -> {ghidra_name} already in sync.")
        else:
            print(f"    -> {ghidra_name} not found in debugger's loaded modules.")


def run_sync_loop(debugger: DebuggerConnector, ghidra: GhidraSyncManager, delay=0.5):
    print("[*] Starting synchronization loop")
    last_ip = None

    try:
        while True:
            current_ip = debugger.get_instruction_pointer()
            addr_hex = hex(current_ip)
            print(current_ip)
            if current_ip != last_ip:
                current_module = debugger.find_module_by_address(current_ip)
                if not current_module:
                    raise Exception(f"Loaded module at {addr_hex} wasn't found. This is probably a bug.")
                else:
                    file_name = current_module['module']
                    ghidra.highlight_instruction(addr_hex=addr_hex)
                    print(f"[+] Jumped to {addr_hex} ({file_name})")
                    last_ip = current_ip
            sleep(delay)
    except KeyboardInterrupt:
        print("\n[!] Sync interrupted.")
    finally:
        debugger.disconnect()


def main():
    opts = get_arguments()
    dbg_connector = DebuggerConnector(ip=opts.ip,
                                      port=opts.port,
                                      arch=opts.arch)
    dbg_connector.connect()

    print(f"[*] Main module base address: {hex(dbg_connector.get_main_module_base_addr())}")
    print(f"[*] Initial instruction pointer: {hex(dbg_connector.get_instruction_pointer())}")

    ghidra = GhidraSyncManager()
    ghidra.connect()

    if opts.rebase:
        sync_loaded_modules(debugger=dbg_connector, ghidra=ghidra)

    run_sync_loop(dbg_connector, ghidra)


if __name__ == "__main__":
    main()
