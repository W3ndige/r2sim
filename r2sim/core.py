from __future__ import annotations

import r2pipe   # type: ignore
import datasketch   # type: ignore
import itertools
import logging

from pathlib import Path
from typing import Dict, List
from collections import namedtuple

from r2sim import utils, radare2, minhash

MatchingFunctions = namedtuple(
    "MatchingFunctions", ["this_func", "other_func", "score"]
)

logger = logging.getLogger("r2sim")


class CoreFile:
    def __init__(self, path: Path):
        self._path = path
        self._r2 = r2pipe.open(str(path))
        self._functions = None

    @property
    def filename(self):
        return self._path.name

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
                "minhash": self.__minhash_from_disassembly(disassembly),
            }

        logging.info(f"File {self.filename} contains {len(functions)} functions")

    def compare_functions(self, other: CoreFile) -> List[MatchingFunctions]:
        matching_functions = []

        function_products = itertools.product(
            self.functions.keys(), other.functions.keys()
        )
        for function_pair in function_products:
            this_function = function_pair[0]
            other_function = function_pair[1]

            this_minhash = self.functions[this_function]["minhash"]
            other_minhash = other.functions[other_function]["minhash"]

            jaccard_coefficient = this_minhash.jaccard(other_minhash)
            if jaccard_coefficient > 0.7:
                logger.info(f"Functions {this_function} and {other_function} are similar with score {jaccard_coefficient}")
                matching_functions.append(
                    MatchingFunctions(
                        this_function, other_function, jaccard_coefficient
                    )
                )

        return matching_functions

    @staticmethod
    def __minhash_from_disassembly(
        disassembly: List[Dict[str, str]]
    ) -> datasketch.LeanMinHash:
        opcodes_list = utils.get_opcodes_function_data(disassembly)

        shingled_disassembly = minhash.n_shingle(opcodes_list)

        return minhash.minhash_data(shingled_disassembly)
