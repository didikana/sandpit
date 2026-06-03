from pathlib import Path

import helper_module


def main() -> str:
    path = Path(__file__).with_name("sample.txt")
    with open(path, "r", encoding="utf-8") as handle:
        return f"{helper_module.helper_value()}:{handle.read().strip()}"


if __name__ == "__main__":
    RESULT = main()
