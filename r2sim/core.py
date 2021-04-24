from __future__ import annotations

import utils
import r2pipe
import radare2
import minhash
import datasketch
import itertools

from typing import Dict, List


class CoreFile:
    def __init__(self, filename: str):
        self._filename = filename
        self._r2 = r2pipe.open(filename)
        self._functions = None

    @property
    def filename(self):
        return self._filename

    @property
    def functions(self):
        return self._functions

    def analyze_file(self):
        self._r2.cmd("aaa")

        functions = radare2.get_all_functions(self._r2)
        self._functions = dict.fromkeys(functions, {})

        for function in functions:
            disassembly = radare2.get_function_disassembly(self._r2, function)
            self._functions[function] = {
                "disassembly": disassembly,
                "minhash": self.__minhash_from_disassembly(disassembly)
            }

        print(f"[*] File {self.filename} contains {len(functions)} functions\n")

    def compare_functions(self, other: CoreFile) -> Dict:
        num_of_matching_functions = 0

        function_products = itertools.product(self.functions.keys(), other.functions.keys())
        for function_pair in function_products:
            this_function = function_pair[0]
            other_function = function_pair[1]

            this_minhash = self.functions[this_function]["minhash"]
            other_minhash = other.functions[other_function]["minhash"]

            jaccard_coefficient = this_minhash.jaccard(other_minhash)
            if jaccard_coefficient > 0.7:
                num_of_matching_functions += 1
                print(
                    f"[*] Functions {this_function} and {other_function} are similar with coefficient equal to {jaccard_coefficient}")

        print(f"\n[*] Number of matching functions: {num_of_matching_functions}\n")

    @staticmethod
    def __minhash_from_disassembly(disassembly: List[Dict[str, str]]) -> datasketch.LeanMinHash:
        opcodes_list = utils.get_opcodes_function_data(disassembly)

        shingled_disassembly = minhash.n_shingle(opcodes_list)

        return minhash.minhash_data(shingled_disassembly)