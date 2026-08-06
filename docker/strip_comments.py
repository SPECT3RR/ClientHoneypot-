"""
Strip comments and docstrings from the Python that ships into the web decoy.

Runs once, inside the image build (docker/Dockerfile.decoy).

The decoy carries four of our modules plus the portal, because it needs them
to run. The *code* is unremarkable -- a bot gate on a corporate portal is an
ordinary anti-fraud measure and explains itself away. The prose around it does
not:

    gate.py                 names the project in its comments
    operator_classifier.py  explains in careful English exactly which
                            behaviours we score and why, so a reader does not
                            have to reverse anything -- they can read the
                            reasoning and rehearse against it

So the comments go. What is left still works and still classifies, but it no
longer teaches. This is not obfuscation and does not pretend to be; someone
determined will still read the logic. It removes the free explanation, which
is the part that costs nothing to take away.

ast.parse + ast.unparse does it: comments are not in the AST at all, and
docstrings are explicit string expression statements that are dropped by hand.
The output is reformatted but semantically identical, and Dockerfile.decoy
imports every module afterwards to prove it still runs.
"""
import ast
import sys
from pathlib import Path

CONTAINERS = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)


def strip(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, CONTAINERS):
            continue
        body = node.body
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            # A function whose whole body is its docstring still needs one
            # statement, or the result will not parse.
            node.body = body[1:] or [ast.Pass()]
    out = ast.unparse(tree)
    ast.parse(out)                      # must still be valid Python
    path.write_text(out + "\n", encoding="utf-8")


if __name__ == "__main__":
    files = [p for root in sys.argv[1:]
             for p in sorted(Path(root).rglob("*.py"))
             if "__pycache__" not in p.parts]
    for path in files:
        strip(path)
    print(f"strip_comments: {len(files)} files stripped")

    # Identifiers survive on purpose -- renaming decoy_page_view would break
    # the collector's parsing. Only prose was ever the problem.
    named = sorted({p.name for p in files
                    if "honeypot" in p.read_text(encoding="utf-8").lower()})
    if named:
        print(f"strip_comments: STILL NAMED: {', '.join(named)}")
        raise SystemExit(1)
    print("strip_comments: no file names the project")
