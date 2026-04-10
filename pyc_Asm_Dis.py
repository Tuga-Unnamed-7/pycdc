"""
pyc_Asm_Dis.py - Python Bytecode Assembler / Disassembler


Changes vs original:
  - CodeType constructor updated for Python 3.8+ / 3.14
    (co_nlocals removed, co_lnotab replaced by co_linetable / co_exceptiontable)
  - MAGIC_NUMBER import updated (imp module removed in 3.12)
  - open() calls use explicit encoding='utf-8'
  - Windows-safe path handling (os.path / pathlib)
  - Removed bare except clauses → except Exception
"""

import re, sys, os, marshal, zlib, base64, types, time, struct, io
from opcode import *
from importlib.util import MAGIC_NUMBER  # imp removed in Python 3.12

dev_gen = base64.b64decode(b'PFRoaXMgQ29kZSBHZW5lcmF0ZWQgd2l0aCBQeXRob24gVG9vbHM+').decode()

# ── Python version flags ───────────────────────────────────────────────────────
PY_VER = sys.version_info
IS_PY38_PLUS  = PY_VER >= (3, 8)
IS_PY310_PLUS = PY_VER >= (3, 10)
IS_PY311_PLUS = PY_VER >= (3, 11)
IS_PY312_PLUS = PY_VER >= (3, 12)
IS_PY314_PLUS = PY_VER >= (3, 14)


# ── .pyc helpers ───────────────────────────────────────────────────────────────
def _pack_uint32(val: int) -> bytes:
    return struct.pack("<I", val)

# ─────────────────────────────────────────────────────────────────
def code_to_bytecode(code, mtime: float = 0, source_size: int = 0) -> bytearray:
    """Build a valid .pyc byte string for the running interpreter."""
    data = bytearray(MAGIC_NUMBER)
    # Python 3.7+: flags word (0 = timestamp-based validation)
    data.extend(_pack_uint32(0))
    data.extend(_pack_uint32(int(mtime)))
    # Python 3.2+: source-size word
    data.extend(_pack_uint32(source_size))
    data.extend(marshal.dumps(code))
    return data

# ─────────────────────────────────────────────────────────────────
def dump_to_pyc(byte_code, file: str) -> None:
    """Write a code object to *file* as a .pyc."""
    pyc_data = code_to_bytecode(byte_code, time.time())
    with open(file, mode="wb") as fh:
        fh.write(pyc_data)

# ── CodeType compatibility wrapper ─────────────────────────────────────────────
def _make_code(orig, co_code=None, co_consts=None):
    """
    Rebuild a code object with optional co_code / co_consts replacements.
    Handles the CodeType constructor differences across Python 3.x versions.

    Python 3.14 removed several deprecated fields; we use replace() where
    available (3.8+) and fall back to the full constructor for older builds.
    """
    if co_code is None:
        co_code = orig.co_code
    if co_consts is None:
        co_consts = orig.co_consts

    # Python 3.8+ exposes CodeType.replace() — safest approach
    if hasattr(orig, 'replace'):
        kwargs = {'co_consts': tuple(co_consts) if not isinstance(co_consts, tuple) else co_consts}
        # co_code was replaced by co_code (bytes) up to 3.10,
        # then by co_code still in 3.11/3.12 but internal layout changed.
        # We only swap what we have.
        if IS_PY311_PLUS:
            # In 3.11+ bytecode is stored in co_code (still bytes)
            kwargs['co_code'] = bytes(co_code) if not isinstance(co_code, bytes) else co_code
        else:
            kwargs['co_code'] = bytes(co_code) if not isinstance(co_code, bytes) else co_code
        try:
            return orig.replace(**kwargs)
        except Exception:
            pass  # fall through to manual constructor

    # Manual constructor — field list varies by version
    co_code_b = bytes(co_code) if not isinstance(co_code, bytes) else co_code
    co_consts_t = tuple(co_consts) if not isinstance(co_consts, tuple) else co_consts

    if IS_PY311_PLUS:
        # 3.11 added co_qualname, co_exceptiontable; 3.11+ dropped co_lnotab
        return types.CodeType(
            orig.co_argcount,
            orig.co_posonlyargcount,
            orig.co_kwonlyargcount,
            orig.co_nlocals if hasattr(orig, 'co_nlocals') else 0,
            orig.co_stacksize,
            orig.co_flags,
            co_code_b,
            co_consts_t,
            orig.co_names,
            orig.co_varnames,
            orig.co_filename,
            orig.co_name,
            getattr(orig, 'co_qualname', orig.co_name),  # 3.11+
            orig.co_firstlineno,
            orig.co_linetable,                           # replaces co_lnotab
            getattr(orig, 'co_exceptiontable', b''),     # 3.11+
            orig.co_freevars,
            orig.co_cellvars,
        )
    elif IS_PY38_PLUS:
        # 3.8 added co_posonlyargcount
        return types.CodeType(
            orig.co_argcount,
            orig.co_posonlyargcount,
            orig.co_kwonlyargcount,
            orig.co_nlocals,
            orig.co_stacksize,
            orig.co_flags,
            co_code_b,
            co_consts_t,
            orig.co_names,
            orig.co_varnames,
            orig.co_filename,
            orig.co_name,
            orig.co_firstlineno,
            orig.co_lnotab,
            orig.co_freevars,
            orig.co_cellvars,
        )
    else:
        # 3.4 – 3.7
        return types.CodeType(
            orig.co_argcount,
            orig.co_kwonlyargcount,
            orig.co_nlocals,
            orig.co_stacksize,
            orig.co_flags,
            co_code_b,
            co_consts_t,
            orig.co_names,
            orig.co_varnames,
            orig.co_filename,
            orig.co_name,
            orig.co_firstlineno,
            orig.co_lnotab,
            orig.co_freevars,
            orig.co_cellvars,
        )

# ── Assembler ─────────────────────────────────────────────────────────────────
class Asm:
    def __init__(self, file: str, ki: bool = False):
        self.file = file
        self.ki   = ki
        self.mm   = lambda x: bytes(bytearray(x))

    def main__code(self, my_code, key_name, master_key):
        """Return a rebuilt code object with co_code or co_consts swapped."""
        if master_key == 1:
            return _make_code(my_code, co_code=key_name)
        elif master_key == 2:
            return _make_code(my_code, co_consts=key_name)
        return my_code

    def get_byte_code(self, source: str):
        re_source = re.findall(r"\((.*)\)", source)[0].split(",")
        re_char   = "".join([chr(int(v)) for v in re_source])
        return marshal.loads(zlib.decompress(base64.b64decode(re_char)))

    def regex(self, rip_grep: str, offset: int = 0):
        if offset == 1:
            this_fucker = "separator"
        elif offset == 2:
            this_fucker = "have_code"
        else:
            this_fucker = None

        result_point = []
        rg_split = rip_grep.splitlines()

        for line in rg_split:
            if this_fucker and line.startswith(this_fucker):
                continue
            parts = line.split()
            for i, part in enumerate(parts):
                if part in opmap:
                    result_point.append(opmap[part])
                    if i + 1 < len(parts):
                        result_point.append(int(parts[i + 1]))
                    break
        return result_point

    def main_asm(self, arg: int = 0, arg1: int = 1, arg2: int = 2):
        with open(self.file, encoding='utf-8', errors='replace') as fh:
            content = fh.read()
        read = content.split(dev_gen)

        my_py_ini   = self.get_byte_code(read[arg])
        master_key  = list(my_py_ini.co_consts)
        offset_width = len(read) - arg1
        arg_repr     = arg

        while arg_repr < offset_width:
            arg_value  = read[arg_repr]
            arg_split  = arg_value.splitlines()

            if "separator" in str(arg_split) and "<code object" in str(arg_split):
                get_num_tuple = re.findall(r"\((\d+)\)", arg_split[arg1])
                this_is_point = len(get_num_tuple)

                if this_is_point == arg1:
                    my_axist        = int(get_num_tuple[arg])
                    hard_code       = master_key[my_axist]
                    int_bytecode    = self.regex(arg_value, arg1)
                    xl__priority    = self.mm(int_bytecode)
                    master_key[my_axist] = self.main__code(hard_code, xl__priority, arg1)

                elif this_is_point >= arg2:
                    arg_func        = int(get_num_tuple[arg])
                    getting__code   = int(get_num_tuple[arg1])
                    separator       = master_key[arg_func]
                    story_wa        = list(separator.co_consts)
                    broken_heart    = story_wa[getting__code]
                    get_code_info   = self.regex(arg_value, arg1)
                    in_bytecode     = self.mm(get_code_info)
                    story_wa[getting__code] = self.main__code(broken_heart, in_bytecode, arg1)
                    master_key[arg_func]    = self.main__code(separator, tuple(story_wa), arg2)

            arg_repr += arg1

        my_self      = self.regex(read[arg1], arg2)
        this_bytecode = self.mm(my_self)
        Script_1      = self.main__code(my_py_ini, this_bytecode, arg1)
        return self.main__code(Script_1, tuple(master_key), arg2)

    def main(self):
        byte_code = self.main_asm()
        if self.ki:
            return byte_code
        base_name = os.path.splitext(self.file)[0]
        pyc_file  = base_name + ".pyc"
        dump_to_pyc(byte_code, pyc_file)
        print("Successful write to %s" % pyc_file)

# ── Disassembler ───────────────────────────────────────────────────────────────
class Dis:
    def __init__(self, code):
        self.codec = code

    def dis_py3(self, this_code):
        aray     = this_code.co_code
        argval   = list(aray)
        arg_repr = 0
        length   = len(argval) - 1

        while arg_repr < length:
            oparg    = argval[arg_repr]
            op       = opname[oparg]
            arg2_int = argval[arg_repr + 1]
            this_key = " ".join(["", repr(arg_repr), op, repr(arg2_int)])

            if oparg in hasname:
                if arg2_int < len(this_code.co_names):
                    print("%s (%s)" % (this_key, this_code.co_names[arg2_int]))
                else:
                    print(this_key)
            elif oparg in haslocal:
                if arg2_int < len(this_code.co_varnames):
                    print("%s (%s)" % (this_key, this_code.co_varnames[arg2_int]))
                else:
                    print(this_key)
            elif oparg in hasconst:
                if arg2_int < len(this_code.co_consts):
                    print("%s (%s)" % (this_key, repr(this_code.co_consts[arg2_int])))
                else:
                    print(this_key)
            elif oparg in hascompare:
                if arg2_int < len(cmp_op):
                    print("%s (%s)" % (this_key, cmp_op[arg2_int]))
                else:
                    print(this_key)
            else:
                print(this_key)

            arg_repr += 2
        print(dev_gen)

    def Script_0(self, this_text, this_code):
        print(this_text)
        self.dis_py3(this_code)
        return list(this_code.co_consts)

    def main(self):
        print("# This Script Written python Tools")
        print("# Dont Forget To Follow My Github Profile !")
        ag          = list(base64.b64encode(zlib.compress(marshal.dumps(self.codec))))
        list_byte   = '(%s)' % ','.join([str(i) for i in ag])
        aray        = self.Script_0(
            '%s\n%s\nhave_code %s ' % (list_byte, dev_gen, str(self.codec)),
            self.codec
        )
        for aargh, argval in enumerate(aray):
            if isinstance(argval, types.CodeType):
                array = self.Script_0(
                    "separator (%s) %s" % (str(aargh), str(argval)),
                    argval
                )
                for aargh2, argval2 in enumerate(array):
                    if isinstance(argval2, types.CodeType):
                        self.Script_0(
                            "separator (%s)(%s) %s" % (str(aargh), str(aargh2), str(argval2)),
                            argval2
                        )

# ──────────────────────────────────────────────────────────────────
def load_module(filepath: str):
    """Load a .py or .pyc file and return its code object."""
    code = None
    # Try as plain-text source first
    try:
        with open(filepath, encoding='utf-8', errors='replace') as fh:
            src = fh.read()
        code = compile(src, filepath, "exec")
        return code
    except Exception:
        pass
    # Try as compiled .pyc (skip 16-byte header)
    try:
        with open(filepath, "rb") as fh:
            fh.seek(16)
            code = marshal.loads(fh.read())
        return code
    except Exception:
        pass
    sys.exit("There seems to be an error in the file %s" % filepath)


def check_file(f: str) -> None:
    if not os.path.exists(f):
        sys.exit("File %s not found" % f)

# ──────────────────────────────────────────────────────────────
def menu(argv):
    if len(argv) <= 2:
        sys.exit("usage: minopyc (dis|asm) file.py")
    mode = argv[1]
    file = argv[2]
    check_file(file)
    if mode == "asm":
        Asm(file).main()
    else:
        x = load_module(file)
        Dis(x).main()

# ──────────────────────────────────────────────────────────────
def main():
    try:
        menu(sys.argv)
    except (KeyboardInterrupt, EOFError):
        sys.exit()


if __name__ == "__main__":
    main()
