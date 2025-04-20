from ghidra_bridge import GhidraBridge

# Establish connection to Ghidra
print("[*] Connecting to GhidraBridge...")
with GhidraBridge(namespace=globals()) as bridge:
    print("[+] Connected to Ghidra.")

    # Remote evaluation to fetch function names and addresses
    functions = bridge.remote_eval(
        "[ (f.getName(), str(f.getEntryPoint())) for f in currentProgram.getFunctionManager().getFunctions(True) ]"
    )

    print("[*] Functions in the current binary:")
    for idx, (name, addr) in enumerate(functions):
        print(f"{idx:03d}: {name} @ {addr}")
        if idx >= 49:
            print("[*] Output truncated at 50 functions.")
            break
