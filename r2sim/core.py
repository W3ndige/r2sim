import utils
import r2pipe
import radare2
import minhash
import datasketch

from typing import Dict, List, Any


def analyze_file(filename: str) -> Dict:
    r2 = r2pipe.open(filename)
    r2.cmd("aaa")

    functions = radare2.get_all_functions(r2)
    data = dict.fromkeys(functions, {})

    for function in functions:
        disassembly = radare2.get_function_disassembly(r2, function)
        data[function] = {
            "disassembly": disassembly,
            "minhash": __minhash_from_disassembly(disassembly)
        }


    return data


def compare_functions(this: Dict[str, Any], other: Dict[str, Any]):
    for this_function in this.keys():
        for other_function in other.keys():
            this_minhash =  this[this_function]["minhash"]
            other_minhash = other[other_function]["minhash"]

            jaccard_coefficient = this_minhash.jaccard(other_minhash)
            if jaccard_coefficient > 0.7:
                print(f"Functions {this_function} and {other_function} are similar with coefficient equal to {jaccard_coefficient}")


def __minhash_from_disassembly(disassembly: List[Dict[str, str]]) -> datasketch.LeanMinHash:
    opcodes_list = utils.get_opcodes_function_data(disassembly)

    shingled_disassembly = minhash.n_shingle(opcodes_list)

    return minhash.minhash_data(shingled_disassembly)