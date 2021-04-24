from typing import List, Dict

def get_opcodes_function_data(function_data: List[Dict[str, str]]) -> List[str]:
    return list(map(lambda x: x["opcode"], function_data))


def get_opcodes_types_function_data(function_data: List[Dict[str, str]]) -> List[str]:
    return list(map(lambda x: x["type"], function_data))