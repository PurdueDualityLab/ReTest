from re_fuzzer.input_generator.regex_generator.re2_regex_generator import RE2RegexGenerator, RE2RegexGeneratorConfig
# import infinty from math
from math import inf
import json

cfg = RE2RegexGeneratorConfig(maxatoms=4, maxops=4, atoms=["a", "b"], ops=RE2RegexGenerator.egrep_ops(), use_random=False)
generator = RE2RegexGenerator(cfg)

OUTPUT_PATH = "/home/bcakar/Research/regex-testing/re-fuzzer/data/exhaustive_dataset.jsonl"

with open(OUTPUT_PATH, "w") as f:
    for pattern in generator.generate(10000):
        f.write(json.dumps({"pattern": pattern}) + "\n")

