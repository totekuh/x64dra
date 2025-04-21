from time import sleep

from x64dra.ghidra_sync_tools import GhidraSyncManager

DEFAULT_DEBUGGER_IP = "127.0.0.1"
DEFAULT_DEBUGGER_PORT = 6589

X64_ARCH = 'x64'
X32_ARCH = 'x32'


def get_arguments():
    from argparse import ArgumentParser
    parser = ArgumentParser(description="x64dbg connector")
    parser.add_argument("-i",
                        "--ip",
                        dest="ip",
                        type=str,
                        default=DEFAULT_DEBUGGER_IP,
                        required=False,
                        help="IP address of the x64dbg API socket. "
                             f"Default is {DEFAULT_DEBUGGER_IP}.")
    parser.add_argument("-p",
                        "--port",
                        dest="port",
                        type=int,
                        default=DEFAULT_DEBUGGER_PORT,
                        required=False,
                        help="Port number of the x64dbg API socket. "
                             f"Default is {DEFAULT_DEBUGGER_PORT}.")
    parser.add_argument("-a",
                        "--arch",
                        dest="arch",
                        type=str,
                        choices=[
                            X64_ARCH,
                            X32_ARCH
                        ],
                        default=X64_ARCH,
                        required=False,
                        help="Debugger architecture. "
                             f"Default is {X64_ARCH}.")
    parser.add_argument("-s",
                        "--sync",
                        dest="sync",
                        action='store_true',
                        required=False,
                        help="Start synchronization between x64dbg and Ghidra. "
                             "The script will start polling the current instruction pointer from x64dbg "
                             "and will invoke Go-To in Ghidra with the address received from x64dbg "
                             "to track it in Ghidra. "
                             "Note that you might need to rebase your modules first by using --rebase "
                             "to make sure the addresses are consistent between the two.")
    parser.add_argument("-r",
                        "--rebase",
                        dest="rebase",
                        action='store_true',
                        required=False,
                        help="Rebase base addresses of the matching modules. "
                             "The script will fetch the base addresses of the loaded modules "
                             "and use them to rebase loaded modules in Ghidra having the same names.")
    parser.add_argument("-ges",
                        "--ghidra-export-symbols",
                        dest="ghidra_export_symbols",
                        type=str,
                        required=False,
                        help="Use this to export function names of the given module from Ghidra "
                             "and use the received symbols to label corresponding addresses in x64dbg, "
                             "so that the CALL instructions in your debugger will have meaningful names. "
                             "Careful: make sure you rebase your modules first.")
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

    def add_label(self, addr: int, label: str):
        self.dbg.set_label_at(addr, label)


def rebase_loaded_modules(debugger: DebuggerConnector, ghidra: GhidraSyncManager):
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
            ip = debugger.get_instruction_pointer()
            if ip == 0:
                print("[*] Instruction pointer is 0 — target not running. Exiting.")
                break
            if ip == last_ip:
                sleep(delay)
                continue
            last_ip = ip

            addr_hex = hex(ip)
            module = debugger.find_module_by_address(ip)
            if not module:
                raise Exception(f"[!] Module not found for address {addr_hex}")

            file_name = module["module"]
            if file_name not in ghidra.get_loaded_files():
                print(f"[-] {file_name} ({addr_hex}) not loaded in Ghidra — skipping.")
                print(f" -> consider importing it from {module['path']}")
            else:
                ghidra.highlight_instruction_in_file(file_name=file_name, addr_hex=addr_hex)
                print(f"[+] Jumped to {addr_hex} in {file_name}")

            sleep(delay)

    except KeyboardInterrupt:
        print("\n[!] Sync interrupted.")
    finally:
        debugger.disconnect()


def export_symbols_from_ghidra(debugger: DebuggerConnector, ghidra: GhidraSyncManager, module_name: str):
    print(f"[*] Exporting symbols from {module_name}")
    module_functions = ghidra.get_functions_in_file(file_name=module_name)
    for name, addr in module_functions.items():
        print(f" -> {name} - {hex(addr)}")
        debugger.add_label(addr=addr, label=name)

    # dbg_connector.dbg.set_function_brackets(start_address=0x140006b70, end_address=0x140006bb0)

def main():
    opts = get_arguments()
    dbg_connector = DebuggerConnector(ip=opts.ip,
                                      port=opts.port,
                                      arch=opts.arch)
    dbg_connector.connect()

    print(f"[*] Main module base address: {hex(dbg_connector.get_main_module_base_addr())}")
    print(f"[*] Current instruction pointer: {hex(dbg_connector.get_instruction_pointer())}")

    ghidra = GhidraSyncManager()
    ghidra.connect()

    if opts.rebase:
        rebase_loaded_modules(debugger=dbg_connector, ghidra=ghidra)
    module_name = opts.ghidra_export_symbols
    if module_name:
        export_symbols_from_ghidra(debugger=dbg_connector, ghidra=ghidra, module_name=module_name)
    if opts.sync:
        run_sync_loop(dbg_connector, ghidra)

if __name__ == "__main__":
    main()