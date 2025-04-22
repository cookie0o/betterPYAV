import ctypes
import sys

def libs(self, current_dir):
    # Windows = .dll
    # Linux   = .so
    if sys.platform.startswith("win"):
        sys_type = "dll"
    else:
        sys_type = "so"

    self.scan_lib = ctypes.CDLL(current_dir+f"/dep/shared_c/scan.{sys_type}")

    self.scan_lib.check_hash_in_file.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    self.scan_lib.check_hash_in_file.restype = ctypes.c_int