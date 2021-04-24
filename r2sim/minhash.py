import logging
import datasketch

from typing import List, Any

logger = logging.getLogger(__name__)

def n_shingle(data: List[Any], n: int = 4) -> List[Any]:
    output = []

    if n == 1:
        return data

    for i in range(len(data) - n - 1):
        output.append(" ".join(data[i : i + n]))

    return output


def minhash_data(data: List[Any]) -> datasketch.LeanMinHash:
    minhash = datasketch.MinHash(num_perm=256)

    for element in data:
        try:
            minhash.update(element.encode("utf-8"))
        except AttributeError as e:
            logger.warning(e)
            continue


    return datasketch.LeanMinHash(
        seed=minhash.seed,
        hashvalues=minhash.hashvalues
    )


def compare_minhashes(m1: datasketch.LeanMinHash, m2: datasketch.LeanMinHash) -> float:
    return m1.jaccard(m2)