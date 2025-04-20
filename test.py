from x64dbg import Debugger
import pefile

if __name__ == "__main__":
    dbg = Debugger(address="127.0.0.1", port=6589)

    if dbg.connect() == True:
        # Get the base address of the current process
        base_address = dbg.get_main_module_base()
        print("Main program base address = {}".format(hex(base_address)))

        # read memory
        byte_array = bytearray()
        for index in range(0,2048):
            read = dbg.get_memory_byte(base_address + index)
            byte_array.append(read)

        # print PE OPTIONAL_HEADER
        pe_ptr = pefile.PE(data = byte_array)
        timedate = pe_ptr.OPTIONAL_HEADER.dump_dict()

        # Read specific fields
        magic = timedate.get("Magic")
        print(magic)

        majorlinkerversion = timedate.get("MajorLinkerVersion")
        print(majorlinkerversion)

        # print PE NT_HEADERS
        nt = pe_ptr.NT_HEADERS.dump_dict()
        print(nt.get("Signature").get("Value"))

        dbg.close_connect()
    else:
        print("Failed to connect debugger")