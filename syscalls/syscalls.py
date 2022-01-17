"""Main program for syscall grabbing."""

import subprocess
from argparse import Namespace
from collections import defaultdict
from dataclasses import field, make_dataclass
from enum import Enum
from logging import getLogger
from os import linesep
from pathlib import Path
from pprint import pformat
from typing import IO, Dict, List, Optional, Tuple
from sys import stdout

from more_itertools import padded
from pygit2 import Repository

from syscalls.architectures import (
    ARCH_SYSCALL_IMPLEMENTATIONS,
    ARCH_SYSTAB,
    ARCHITECTURE,
    ALL_ARCHES,
    GENERIC_SYSCALL_IMPLEMENTATIONS,
)
from syscalls.parser.parser import TBL, CLang, SyscallDefinition

logger = getLogger(__name__)


class OUTPUT_FMT(str, Enum):
    """
    Enumeration of output formats.
    """

    JSON = "json"
    MD = "md"


class SyscallParser:
    """
    Parses the linux source tree for syscall numbers and builds a list of
    syscalls.
    """

    def __init__(self, args: Namespace):
        self.arch: Tuple[Tuple[ARCHITECTURE, Optional[int]]] = (
            (
                *map(
                    lambda p: (
                        ARCHITECTURE(p[0]),
                        int(p[1]) if len(p) > 1 else None,
                    ),
                    map(lambda p: p.split(","), args.arch),
                ),
            )
            if args.arch
            else ALL_ARCHES
        )
        self.path: Path = args.path
        self.fmt: OUTPUT_FMT = args.fmt

        self.check_path()

        self.repo: Repository = Repository(self.path)
        self.commit, self.ref = None, None
        self.tag: str = args.tag if args.tag else "master"

        self.check_tag()
        self.mapping: defaultdict = defaultdict(dict)
        self.defs: Dict[Path, List[SyscallDefinition]] = {}
        self.outfile = (
            stdout if not args.outfile is not None else args.outfile.open("w")
        )

    def check_path(self) -> None:
        """
        Check that the given path is sane.
        """

        # Check path
        if not all(
            (
                self.path.exists(),
                self.path.is_dir(),
                self.path.name == "linux",
                (self.path / ".git").exists(),
            )
        ):
            raise ValueError(f"{self.path} is not a linux source tree.")

    def check_tag(self) -> None:
        """
        Check that the requested tag is sane.
        """

        try:
            self.commit, self.ref = self.repo.resolve_refish(self.tag)
        except KeyError as e:
            raise ValueError(f"{self.tag} is not a valid tag.") from e

    def parse_arch_bits(self, arch: ARCHITECTURE, bits: int) -> None:
        """
        Parse the systab file for the given architecture and bits.

        :param arch: The architecture to parse.
        :param bits: The bits to parse.
        """
        arch_sysnums = []
        generic_sysnums = self.parse_generic_syscall_numbers(bits)
        arch_sysnums = list(self.parse_arch_syscall_numbers(arch, bits))
        arch_sysnums_nums = (
            *map(
                lambda x: x.number,
                filter(lambda sn: hasattr(sn, "number"), arch_sysnums),
            ),
        )
        arch_sysnums_fields = (
            (
                *map(
                    lambda f: (f, Optional[str], field(default=None)),
                    arch_sysnums[0].__dataclass_fields__,
                ),
            )
            if arch_sysnums
            else (
                ("number", Optional[str], field(default=None)),
                ("name", Optional[str], field(default=None)),
                ("entry_point", Optional[str], field(default=None)),
            )
        )

        # Backfill missing arch specific syscall numbers
        for name, syscall in generic_sysnums.items():
            # __NR_syscalls isn't a syscall
            if name == "syscalls":
                continue

            if str(syscall) not in arch_sysnums_nums:
                try:
                    arch_sysnums.append(
                        make_dataclass("TBL", arch_sysnums_fields)(
                            number=syscall, name=name
                        )
                    )
                except TypeError as e:
                    raise ValueError(f"{e}: {arch_sysnums_fields}") from e

        # Parse the syscall function prototypes
        generic_syscall_defineset = self.parse_generic_sysdefs()
        arch_syscall_defineset = self.parse_arch_sysdefs(arch, bits)

        arch_syscall_names = []
        for defnlist in arch_syscall_defineset.values():
            for defn in defnlist:
                arch_syscall_names.append(defn.name)

        for path, generic_defnlist in generic_syscall_defineset.items():
            for defn in generic_defnlist:
                if defn.name not in arch_syscall_names:
                    arch_syscall_defineset[path].append(defn)

        # We have syscall numbers and syscall function prototypes now.
        for defnlist in arch_syscall_defineset.values():
            for defn in defnlist:
                for sysnum in arch_sysnums:
                    if (sysnum.name is not None and defn.name == sysnum.name) or (
                        sysnum.entry_point is not None
                        and defn.name == sysnum.entry_point[4:]
                    ):
                        defn.number = int(sysnum.number)
                        defn.entry_points = []

                        if (
                            hasattr(sysnum, "entry_point")
                            and sysnum.entry_point is not None
                        ):
                            defn.entry_points.append(sysnum.entry_point)
                        if (
                            hasattr(sysnum, "compat_entry_point")
                            and sysnum.compat_entry_point is not None
                        ):
                            defn.entry_points.append(sysnum.compat_entry_point)
                        break
                else:
                    logger.error(
                        f"Could not find a sysnum for {defn.name}. "
                        "Assuming it doesn't exist on this arch."
                        # f" Table\n:{linesep.join(map(str, arch_sysnums))}"
                    )

        self.output((arch, bits), self.outfile, arch_syscall_defineset)

    def parse(self) -> None:
        """
        Parse the source tree for syscall information.
        """

        # Parse out syscall metadata
        for arch, bits in self.arch:
            try:
                self.parse_arch_bits(arch, bits)
            except Exception as e:
                logger.error(e)

    def output_json(
        self,
        s: Tuple[ARCHITECTURE, int],
        f: IO,
        defs: Dict[Path, List[SyscallDefinition]],
    ) -> None:
        """
        Output the parsed syscall information in JSON format.

        :param f: The file to write to.
        :param defs: The syscall definitions to output.
        """

        output = {}

        for defnlist in defs.values():
            for defn in defnlist:
                output[defn.number] = {
                    "number": defn.number,
                    "name": defn.name,
                    "entry_points": defn.entry_points,
                    "arguments": defn.arguments,
                }
        f.write(pformat(output) + "\n")

    def output_md(
        self,
        s: Tuple[ARCHITECTURE, int],
        f: IO,
        defs: Dict[Path, List[SyscallDefinition]],
    ) -> None:
        """
        Output the parsed syscall information in Markdown format.

        :param f: The file to write to.
        :param defs: The parsed syscall information.
        """

        f.write(f"\n##  {s[0]} {s[1]}-bit\n\n")

        f.write(
            "| Syscall # | Name | Entry Points | # Arguments "
            "| arg0 | arg1 | arg2 | arg3 | arg4 | arg5 | arg6 |\n"
        )
        f.write("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")

        defns = []

        for defnlist in defs.values():
            for defn in defnlist:
                defns.append(defn)

        defns.sort(key=lambda x: x.number)

        for defn in defns:
            if defn.number != -1:
                f.write(
                    f"{defn.number} | {defn.name} | {', '.join(defn.entry_points)} "
                    f"| {defn.nargs} | "
                    f"{' | '.join(map(lambda a: ' '.join(a), padded(defn.args, '-', 7)))} |\n"
                )

    def output(
        self,
        s: Tuple[ARCHITECTURE, int],
        f: IO,
        defs: Dict[Path, List[SyscallDefinition]],
    ) -> None:
        """
        Output the parsed syscall information.

        :param f: The file to write to.
        :param defs: The syscall definitions to output.
        """
        if self.fmt == OUTPUT_FMT.JSON:
            self.output_json(s, f, defs)
        elif self.fmt == OUTPUT_FMT.MD:
            self.output_md(s, f, defs)

    def parse_generic_sysdefs(self) -> Dict[Path, List[SyscallDefinition]]:
        """
        Get raw generic syscall definitions.
        """

        parser = CLang()

        generic_sysdefs = defaultdict(list)

        for syscall_impl in GENERIC_SYSCALL_IMPLEMENTATIONS:
            p = self.path / syscall_impl
            parser.parse(p.open("rb").read())
            generic_sysdefs[p].extend(parser.extract_syscalls())

        return generic_sysdefs

    def parse_arch_sysdefs(
        self, arch: ARCHITECTURE, bits: int
    ) -> Dict[Path, List[SyscallDefinition]]:
        """
        Parse the syscall definitions for a specific architecture.

        :param arch: The architecture to parse.
        :param bits: The number of bits to preprocess for.
        """

        parser = CLang()
        arch_sysdefs = defaultdict(list)

        for syscall_impl in ARCH_SYSCALL_IMPLEMENTATIONS[arch]:
            p = self.path / syscall_impl
            parser.parse(p.open("rb").read())
            arch_sysdefs[p].extend(parser.extract_syscalls())

        return arch_sysdefs

    def arch_systab(self, arch: ARCHITECTURE, bits: int) -> Path:
        """
        Get the systab file for the given architecture and bits.
        """
        return self.path / ARCH_SYSTAB[arch][bits]

    def parse_arch_syscall_numbers(self, arch: ARCHITECTURE, bits: int) -> Tuple[TBL]:
        """
        Parse the syscall numbers for a specific architecture.

        :param arch: The architecture to parse.
        :param bits: The number of bits to preprocess for.
        """
        tab = self.arch_systab(arch, bits)

        if not tab.is_file():
            return tuple()

        tparser = TBL()
        with tab.open("rb") as f:
            entries = tparser.parse(f.read())
            return entries

    def parse_generic_syscall_numbers(self, bits: int) -> Dict[str, int]:
        """
        Get architecture independent syscall information first.

        :param bits: Number of bits to preprocess for.
        """
        asm_generic_uapi_unistd = (
            self.path / "include" / "uapi" / "asm-generic" / "unistd.h"
        )
        pp_file = self.preprocess(bits, asm_generic_uapi_unistd)
        parser = CLang()
        parser.parse(pp_file)

        generic_mapping = {}
        for ident, value in parser.extract_defines():
            if ident.startswith("__NR"):
                try:
                    generic_mapping["_".join(ident.split("_")[3:])] = int(value)
                except ValueError:
                    generic_mapping["_".join(ident.split("_")[3:])] = generic_mapping[
                        "_".join(value.split("_")[3:])
                    ]
        return generic_mapping

    def preprocess(self, bits: int, file: Path) -> bytes:
        """
        Preprocess a file with clang and return the contents.

        :param bits: Number of bits to preprocess for.
        :param file: File to preprocess.
        """

        cmd = "clang -E -D__BITS_PER_LONG={bits} -dM {relpath}".format(
            bits=bits, relpath=file.relative_to(self.path)
        )

        res = subprocess.run(
            cmd, capture_output=True, cwd=self.path, check=True, shell=True
        )

        assert res.returncode == 0, f"{cmd} failed with exit code {res.returncode}"

        return res.stdout


def run(args: Namespace) -> None:
    """
    Main entrypoint for syscall collection.

    :param args: Command line argument namespace.
    """
    parser = SyscallParser(args)
    parser.parse()
