import pcre
import json

from re_fuzzer.input_generator.regex_generator.grammarinator_generator import (
        GrammarinatorGenerator,
        GrammarinatorGeneratorConfig,
    )

config = GrammarinatorGeneratorConfig(
    generator_path="./resources/grammars/PCREGenerator.py",
    random_seed=42,
    max_depth=64,
    max_tokens=32,
    memo_size=100000,
    unique_attempts=3
)
generator = GrammarinatorGenerator(config)

OUTPUT_PATH = "/home/bcakar/Research/regex-testing/re-fuzzer/data/random_dataset.jsonl"

with open(OUTPUT_PATH, "w") as f:
    success = 0
    for pattern in generator.generate(1000000):
        if pattern == "":
            continue
        try:
            pcre.compile(pattern)
            success += 1
            f.write(json.dumps({"pattern": pattern}) + "\n")
        except Exception as e:
            continue
        if success >= 10000:
            break