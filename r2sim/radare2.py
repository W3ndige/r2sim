import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def get_all_functions(r2, min_func_length: int = 64) -> Optional[List]:
    raw_functions_json = r2.cmdj("aflj")

    if not raw_functions_json:
        logger.warning("R2 didn't find any functions in file.")
        return None

    return list(map(lambda x: x["name"], filter(lambda x: x["size"] > min_func_length, raw_functions_json)))


def get_function_disassembly(r2, function_name: str) -> Optional[Dict[str, List]]:
    if ";" in function_name:
        logger.error("Found ';' in function name.")
        return None

    raw_disassembly_json = r2.cmdj(f"pdfj @{function_name}")

    if not raw_disassembly_json:
        logger.warning(f"R2 didn't find disassembly for function {function_name}")
        return None

    disassembly = []
    raw_opcodes = raw_disassembly_json["ops"]
    for raw_opcode in raw_opcodes:
        try:
            disassembly.append({
                "type": raw_opcode["type"],
                "offset": raw_opcode["offset"],
                "opcode": raw_opcode["opcode"]
            })
        except KeyError:
            logger.warning(f"Information for opcode at offset {raw_opcode['offset']} of {function_name} not found")

    return disassembly
