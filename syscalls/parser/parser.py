"""C Parser utilities for extracting sycall information from C source code."""

from dataclasses import dataclass, field, make_dataclass
from pathlib import Path
from re import findall
from typing import Generator, List, Optional, Tuple

from more_itertools import chunked, split_when, windowed
from tree_sitter import Language, Node, Parser


@dataclass
class SyscallDefinition:
    nargs: int
    name: str
    args: List[List[str]]
    entry_points: List[str] = field(default_factory=list)
    number: int = -1


class CLangInitializer:
    """
    Set up the C language parser and compile it if necessary.
    """

    PARSER_LIB_PATH = (
        Path(__file__).parents[1].with_name("third_party") / "tree-sitter-c"
    )
    PARSER_BUILD_PATH = Path(__file__).parents[1].with_name("build") / "parsers.so"
    clang: Optional[Language] = None

    @classmethod
    def init(cls) -> None:
        """
        Check the source tree for the C language parser.
        If it is not present, compile it.
        """
        Language.build_library(
            str(cls.PARSER_BUILD_PATH.resolve()), [str(cls.PARSER_LIB_PATH.resolve())]
        )

        cls.clang = Language(cls.PARSER_BUILD_PATH.resolve(), "c")

    @classmethod
    def get_parser(cls) -> Parser:
        """
        Get a parser for the C language.
        """
        parser = Parser()
        parser.set_language(cls.clang)
        return parser


class CLang:
    """
    Wrapper for the C language parser.
    """

    def __init__(self) -> None:
        """
        Initialize the C language parser.
        """
        CLangInitializer.init()
        self.parser = CLangInitializer.get_parser()
        self.clang = CLangInitializer.clang

    def parse(self, text: bytes) -> None:
        """
        Parse some source code.
        """
        self.tree = self.parser.parse(text)

    def dump(self) -> None:
        """
        Dump the parse tree.
        """
        print(self.tree.root_node.sexp())

    def extract_defines(self) -> Generator[Tuple[str, str], None, None]:
        """
        Extract #define statements from the parse tree.

        Returns pairs of (name, value).
        """
        cursor = self.tree.root_node.walk()
        cursor.goto_first_child()
        while cursor.goto_next_sibling():
            if cursor.node.type == "preproc_def":
                ident = cursor.node.children[1]
                value = cursor.node.children[2]
                yield ident.text.strip().decode("utf-8"), value.text.strip().decode(
                    "utf-8"
                )

    def extract_defns_ident(self, ident: Node) -> Optional[SyscallDefinition]:
        """
        Extract syscall definitions from the parse tree.

        :param ident: The identifier node to extract syscall definitions from.
        """
        if ident.text.strip().decode("utf-8").startswith("SYSCALL_DEFINE"):
            def_fun = ident.children[0].text.decode("utf-8")
            arglist = ident.children[1]
            args = [[]]
            fun = arglist.children[1].text.decode("utf-8")
            for arg in arglist.children[3:]:
                if (
                    arg.type == "identifier"
                    or arg.type == "ERROR"
                    or arg.type == "binary_expression"
                ):
                    args[-1].append(arg.text.decode("utf-8"))
                elif args[-1] != []:
                    args.append([])

            compargs = []
            for x in chunked(args, 2):
                sub = []
                for v in x:
                    for a in v:
                        sub.extend(a.split())
                if sub:
                    compargs.append(sub)

            try:
                arg_num = int(def_fun[-1])
            except:
                arg_num = 0

            assert arg_num == len(compargs), (
                f"args count {arg_num} doesn't match detected argument count "
                f"of {compargs} for syscall "
                f"{ident.text.strip().decode('utf-8')}: "
                f"{':'.join(map(lambda a: a.type, arglist.children))}."
            )

            return SyscallDefinition(
                nargs=arg_num,
                name=fun,
                args=compargs,
            )
        return None

    def extract_syscalls(self) -> Generator[SyscallDefinition, None, None]:
        """
        Extract SYSCALL_DEFINE(...) statements from the parse tree.

        Returns tuples of the syscall define arguments.
        """
        exp_stmt_query = self.clang.query(
            """
            (expression_statement (call_expression) @cexp)
            """
        )

        fun_def_query = self.clang.query(
            """
            (function_definition type: (type_identifier) @tid declarator: (parenthesized_declarator (identifier)+ @ident))
            """
        )

        estmts = exp_stmt_query.captures(self.tree.root_node)
        for capture in map(lambda c: c[0], estmts):
            if "SYSCALL_DEFINE" in capture.text.decode(
                "utf-8"
            ) and not "COMPAT" in capture.text.decode("utf-8"):
                if self.extract_defns_ident(capture) is not None:
                    yield self.extract_defns_ident(capture)
        fndefs = fun_def_query.captures(self.tree.root_node)
        for defn in split_when(fndefs, lambda _, y: y[1] == "tid"):
            if "SYSCALL_DEFINE" in defn[0][0].text.decode(
                "utf-8"
            ) and not "COMPAT" in defn[0][0].text.decode("utf-8"):
                for ident in defn[1:]:
                    yield SyscallDefinition(
                        nargs=0,
                        name=ident[0].text.decode("utf-8"),
                        args=[],
                    )


class TBL:
    """.tbl file parser"""

    def __init__(self) -> None:
        """
        Initialize tbl parser
        """
        self.tbl = None

    def parse(self, data: bytes) -> Tuple["TBL"]:
        """
        Parse some source code.
        """
        text = data.decode("utf-8")

        def remap(s: str) -> str:
            # Override num -> number :/ why is this not compat? IDK
            if s == "num":
                return "number"
            return s

        cols = (
            *map(
                lambda e: remap(e.replace(" ", "_")),
                findall(
                    r"<([a-z ]+)>",
                    next(
                        filter(
                            lambda w: "format is:" in w[0],
                            windowed(text.splitlines(), 2),
                        )
                    )[1],
                ),
            ),
        )

        fields = []
        for col in cols:
            fields.append((col, Optional[str], field(default=None)))
        etype = make_dataclass("TBL", fields)

        inits = (
            *map(
                lambda l: dict(zip(cols, l.split())),
                filter(
                    # Only filter >= 2 because we only *need* the syscall name and number
                    lambda l: not l.startswith("#") and len(l.split()) >= 2,
                    text.splitlines(),
                ),
            ),
        )

        entries = (*map(lambda i: etype(**i), inits),)

        return entries
