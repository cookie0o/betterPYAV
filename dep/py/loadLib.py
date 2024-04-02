import ctypes

def libs(self, current_dir):
    self.scan_lib = ctypes.CDLL(current_dir+"/dep/shared_c/scan.so")
    self.scan_lib.check_hash_in_file.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    self.scan_lib.check_hash_in_file.restype = ctypes.c_int