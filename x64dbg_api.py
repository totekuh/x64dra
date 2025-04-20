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
    return parser.parse_args()



class X64DebuggerConnector:
    def __init__(self, ip: str, port: int, arch: str):
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


def main():
    options = get_arguments()
    ip = options.ip
    port = options.port
    arch = options.arch
    x64dbg_connector = X64DebuggerConnector(ip=ip, port=port, arch=arch)
    x64dbg_connector.connect()
    main_module_base_addr = hex(x64dbg_connector.get_main_module_base_addr())
    print(f"[*] Main module base address: {main_module_base_addr}")

    print(f"[*] Current instruction pointer: {hex(x64dbg_connector.get_instruction_pointer())}")

    ghidra_sync_manager = GhidraSyncManager()
    ghidra_sync_manager.connect()

    print("[*] Starting synchronization loop")
    try:
        while True:
            instruction_pointer = hex(x64dbg_connector.get_instruction_pointer())
            ghidra_sync_manager.highlight_instruction(addr_hex=instruction_pointer)
            sleep(0.5)
    except KeyboardInterrupt:
        print()
        print("Interrupted")
    finally:
        x64dbg_connector.disconnect()


if __name__ == "__main__":
    main()