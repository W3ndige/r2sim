import sys

import core

data_1 = core.analyze_file(sys.argv[1])
data_2 = core.analyze_file(sys.argv[2])

core.compare_functions(data_1, data_2)
