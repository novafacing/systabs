from argparse import ArgumentParser
from pathlib import Path

from syscalls.architectures import ARCHITECTURE
from syscalls.syscalls import OUTPUT_FMT, run

if __name__ == "__main__":
    parser = ArgumentParser(prog="syscalls")

    parser.add_argument(
        "--tag",
        "-t",
        required=False,
        help="Tag to get syscalls for. Defaults to latest.",
    )
    parser.add_argument(
        "--path", "-p", type=Path, required=True, help="Path to linux repository."
    )
    parser.add_argument(
        "--arch",
        "-a",
        type=str,
        nargs="+",
        action="extend",
        metavar="ARCH",
        required=False,
        help=(
            "Architecture(s) to get syscalls for. Defaults to all. "
            "Architectures can optionally be followed by a number to override the "
            "bitness of the architecture. For example, '-a x86,64' will get syscalls "
            "for x86_64, while '-a x86' will get syscalls for x86_32."
        ),
    )
    parser.add_argument(
        "--fmt",
        "-f",
        type=str,
        choices=list(map(lambda v: v.value, OUTPUT_FMT)),
        required=False,
        default="md",
        help="Output format. Defaults to markdown.",
    )

    args = parser.parse_args()

    run(args)
