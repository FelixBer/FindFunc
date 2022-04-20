inida = True
try:
    import idc
    import idaapi
    import idautils
    import ida_bytes
    import ida_ua
    import ida_pro
except:
    inida = False

from PyQt5.Qt import QApplication

### config

# print the result of the copy operation to IDA log
logresult = True


### helper


def copy_to_clip(data):
    QApplication.clipboard().setText(data)


is64 = idaapi.get_inf_structure().is_64bit()

### copy all


def copy_all_bytes():
    """
    Copy all instruction bytes as hex string to clipboard
    e.g. 11 22 33 44
    """
    start = idc.read_selection_start()
    end = idc.read_selection_end()
    if idaapi.BADADDR in (start, end):
        ea = idc.here()
        start = idaapi.get_item_head(ea)
        end = idaapi.get_item_end(ea)
    data = idc.get_bytes(start, end - start).hex()
    data = ' '.join([data[i:i + 2] for i in range(0, len(data), 2)])
    copy_to_clip(data)
    if logresult:
        print("copy_all_bytes:     ", data)


### copy no-imm


def int_as_bytes(integer, size):
    # print(ida_pro.__MF__)  # 0 = little endian, 1 = big endian or info.is_be()
    # print(integer, hex(integer), size)
    try:
        return integer.to_bytes(size, byteorder='little', signed=integer < 0)
    except OverflowError:
        return None


def is_neg(addr):
    if is64:
        return addr & 0x8000000000000000
    else:
        return addr & 0x80000000


masks = [(8, 0), (4, 0xffffffff00000000), (2, 0xffffffffffff0000), (1, 0xffffffffffffff00)]


def get_bytes_without_imm(ins) -> str:
    """
    Copies instruction bytes for given instruction, masking out
    any immediate values.
    This is a "best effort" with the IDA api, and there may be a few cases
    where it only works partially.
    For a 100% correct solution we would have to ship our own disasm library.
    """
    bytedata = ida_bytes.get_bytes(ins.ea, ins.size)
    orgbytelen = len(bytedata)
    # print("inbytes: ", bytedata)
    for op in reversed(ins.ops):
        if op.type == idaapi.o_void:
            continue
        if op.type in (idc.o_phrase, idc.o_reg):
            # have no immediatae (exception: some strange encodings where it is zero)
            continue
        if op.type in (idc.o_near, idc.o_far):
            size = ida_ua.get_dtype_size(op.dtype)
            asbyt = int_as_bytes(op.addr, size)
            if asbyt and bytedata.endswith(asbyt):
                bytedata = bytedata[:-size]
                continue
            # only x64: rip-rel
            asbyt = int_as_bytes(op.addr - ins.ea - ins.size, size)
            if asbyt and bytedata.endswith(asbyt):
                bytedata = bytedata[:-size]
                continue
        if op.type == idaapi.o_imm:
            size = ida_ua.get_dtype_size(op.dtype)
            asbyt = int_as_bytes(op.value, size)
            if asbyt and bytedata.endswith(asbyt):
                bytedata = bytedata[:-size]
                continue
            # dtype doesnt indicate the imm size, but rather destination size
            # usually equivalent, but not always, e.g. add r64, imm
            for size, mask in masks:
                cur_val = op.value & ~mask
                asbyt = int_as_bytes(cur_val, size)
                if asbyt and bytedata.endswith(asbyt):
                    bytedata = bytedata[:-size]
                    break
        if op.type in (idaapi.o_mem, idc.o_displ):
            for size, mask in masks:
                cur_adr = op.addr & ~mask
                asbyt = int_as_bytes(cur_adr, size)
                if asbyt and bytedata.endswith(asbyt):
                    bytedata = bytedata[:-size]
                    break
                # only x64: rip-rel
                asbyt = int_as_bytes(op.addr - ins.ea - ins.size, size)
                if asbyt and bytedata.endswith(asbyt):
                    bytedata = bytedata[:-size]
                    break

    result = ""
    for x in bytedata:
        result += " {:02x}".format(x)
    for x in range(orgbytelen - len(bytedata)):
        result = result + " ??"
    # print("result: ", result)
    return result.strip()


def copy_bytes_no_imm():
    """
    Copy all instruction bytes as hex string to clipboard, masking out immediate values
    e.g. 11 22 ?? ??
    """
    start = idc.read_selection_start()
    end = idc.read_selection_end()
    if idaapi.BADADDR in (start, end):
        ea = idc.here()
        start = idaapi.get_item_head(ea)
        end = idaapi.get_item_end(ea)
    result = ""
    processed = 0
    while start + processed < end:
        ins = idautils.DecodeInstruction(start + processed)
        if not ins:
            processed += 1
            continue
        processed += ins.size
        result += " " + get_bytes_without_imm(ins)
    if logresult:
        print("copy_bytes_no_imm: ", result)
    copy_to_clip(result)


###
### copy opcodes

class bytegetter:
    """
    Helper that returns a byte of the given instruction on
    every self.getb() call, or None if no more bytes
    """
    def __init__(self, ins):
        self.done = 0
        self.bytedata = ida_bytes.get_bytes(ins.ea, ins.size)

    def getb(self):
        if self.done < len(self.bytedata):
            self.done = self.done + 1
            return self.bytedata[self.done - 1]
        return None


legacyprefix = {0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x2E, 0x3E, 0x66, 0x67}


def getopc(ins):
    """
    Returns instruction bytes for given instruction, masking out
    any bytes that are NOT the opcodes of the instruction.
    This is a "best effort" without a dedicated disasm library, and there may be few cases
    where it only works partially.
    For a 100% correct solution we would have to ship our own disasm library.
    """
    res = []
    unk = "??"
    getter = bytegetter(ins)

    x = getter.getb()
    while x in legacyprefix:
        res += [x]  # legacy prefix
        x = getter.getb()

    while x and (x & 0xF0) == 0x40:
        res += [unk]  # REX prefix
        x = getter.getb()

    if x == 0x0F:  # multibyte opcode
        y = getter.getb()
        if y == 0x38 or y == 0x3A:
            res += [x, y, getter.getb()]
            return res
        if y == 0x0F:  # 3Dnow!
            res += [x, y]  # + last byte is (ab)used as an opcode...
            return res
        res += [x, y]
        return res

    # some say these are only for x64...
    if x == 0x62:  # EVEX: 4 + 1 opcode
        getter.getb()
        getter.getb()
        getter.getb()
        res += [x, unk, unk, unk, getter.getb()]
        return res
    if x == 0xC4:  # 3 byte evex
        getter.getb()
        getter.getb()
        res += [x, unk, unk, getter.getb()]
        return res
    if x == 0xC5:  # 2 byte evex
        getter.getb()
        res += [x, unk, getter.getb()]
        return res
    if x == 0x8F:  # 3 byte xop
        getter.getb()
        getter.getb()
        res += [x, unk, unk, getter.getb()]
        return res

    res += [x]  # normal opcode
    return res


def get_only_opcodes(ins) -> str:
    """
    Convert getopc(ins) result to string
    """
    res = getopc(ins)
    result = ""
    for x in res:
        if x is None:
            continue
        elif x == "??":
            result += " ??"
        else:
            result += " {:02x}".format(x)
    for x in range(ins.size - len(res)):
        result += " ??"
    # print("fin: ", result)
    return result.strip()


def copy_only_opcodes():
    """
    Copy all instruction bytes as hex string to clipboard,
    masking out any bytes that are not the actual opcode
    e.g. 11 ?? ?? ??
    """
    start = idc.read_selection_start()
    end = idc.read_selection_end()
    if idaapi.BADADDR in (start, end):
        ea = idc.here()
        start = idaapi.get_item_head(ea)
        end = idaapi.get_item_end(ea)
    result = ""
    processed = 0
    while start + processed < end:
        ins = idautils.DecodeInstruction(start + processed)
        if not ins:
            processed += 1
            continue
        processed += ins.size
        result += " " + get_only_opcodes(ins)
    if logresult:
        print("copy_only_opcodes: ", result)
    copy_to_clip(result)


def copy_only_disasm():
    """
    Copy all instructions as diassembly as provided by IDA
    """
    start = idc.read_selection_start()
    end = idc.read_selection_end()
    if idaapi.BADADDR in (start, end):
        ea = idc.here()
        start = idaapi.get_item_head(ea)
        end = idaapi.get_item_end(ea)
    result = ""
    processed = 0
    while start + processed < end:
        ins = idc.GetDisasm(start + processed)
        size = idc.next_head(start + processed) - (start + processed)
        if not size:
            size = 1
        processed += size
        if ins:
            result += ins + "\n"
    if logresult:
        print("copy_only_disasm: ", result)
    copy_to_clip(result)

###

# https://wiki.osdev.org/X86-64_Instruction_Encoding#VEX.2FXOP_opcodes
# https://github.com/capstone-engine/capstone/blob/master/arch/X86/X86DisassemblerDecoder.c#L749
