"""AST-based checks for high-signal insecure Python call patterns."""

import ast
from pathlib import Path

from codexlens.models import Finding, FindingConfidence, Severity

_SHELL_CALLS = {"os.system", "os.popen"}
_SUBPROCESS_CALLS = {
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.run",
}
_PICKLE_CALLS = {"pickle.load", "pickle.loads"}
_REQUEST_CALL_SUFFIXES = {
    ".delete",
    ".get",
    ".head",
    ".options",
    ".patch",
    ".post",
    ".put",
    ".request",
}


def find_ast_findings(path: Path, tree: ast.AST) -> tuple[Finding, ...]:
    """Return AST findings for *tree* without evaluating the scanned code."""

    aliases = _ImportAliasCollector().collect(tree)
    visitor = _SecurityCallVisitor(path, aliases)
    visitor.visit(tree)
    return tuple(visitor.findings)


class _ImportAliasCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}

    def collect(self, tree: ast.AST) -> dict[str, str]:
        self.visit(tree)
        return self.aliases

    def visit_Import(self, node: ast.Import) -> None:
        for imported in node.names:
            local_name = imported.asname or imported.name.split(".", maxsplit=1)[0]
            self.aliases[local_name] = imported.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            return
        for imported in node.names:
            local_name = imported.asname or imported.name
            self.aliases[local_name] = f"{node.module}.{imported.name}"


class _SecurityCallVisitor(ast.NodeVisitor):
    def __init__(self, path: Path, aliases: dict[str, str]) -> None:
        self.path = path
        self.aliases = aliases
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._expression_name(node.func)
        if call_name in _SHELL_CALLS and node.args and _is_dynamic_text(node.args[0]):
            self._add(
                node,
                rule_id="CL101",
                title="Dynamic command passed to a shell",
                severity=Severity.HIGH,
                description="A dynamically constructed command reaches an OS shell call.",
                cwe="CWE-78",
            )
        elif call_name in _SUBPROCESS_CALLS and _uses_literal_shell_true(node):
            self._add(
                node,
                rule_id="CL102",
                title="Subprocess shell execution enabled",
                severity=Severity.HIGH,
                description=(
                    "A subprocess call enables shell=True, which can allow command injection."
                ),
                cwe="CWE-78",
            )
        elif call_name in {"eval", "exec"}:
            self._add(
                node,
                rule_id="CL103",
                title="Dynamic code execution",
                severity=Severity.HIGH,
                description="Dynamic code execution can run untrusted input as Python code.",
                cwe="CWE-95",
            )
        elif call_name in _PICKLE_CALLS:
            self._add(
                node,
                rule_id="CL104",
                title="Unsafe pickle deserialization",
                severity=Severity.HIGH,
                description=(
                    "Pickle data can execute code when it is deserialized from an untrusted source."
                ),
                cwe="CWE-502",
            )
        elif call_name == "yaml.load" and not self._uses_safe_yaml_loader(node):
            self._add(
                node,
                rule_id="CL105",
                title="Unsafe YAML deserialization",
                severity=Severity.HIGH,
                description="yaml.load can construct unsafe Python objects without a safe loader.",
                cwe="CWE-502",
            )
        elif call_name.endswith((".execute", ".executemany")) and node.args and _is_dynamic_text(
            node.args[0]
        ):
            self._add(
                node,
                rule_id="CL106",
                title="Dynamically constructed database query",
                severity=Severity.MEDIUM,
                description=(
                    "A dynamically constructed query reaches execute(); use parameterized queries."
                ),
                cwe="CWE-89",
            )
        elif _is_request_call(call_name) and _uses_literal_verify_false(node):
            self._add(
                node,
                rule_id="CL107",
                title="TLS certificate verification disabled",
                severity=Severity.MEDIUM,
                description="An HTTP request disables TLS certificate verification.",
                cwe="CWE-295",
            )

        self.generic_visit(node)

    def _add(
        self,
        node: ast.Call,
        *,
        rule_id: str,
        title: str,
        severity: Severity,
        description: str,
        cwe: str,
    ) -> None:
        self.findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                confidence=FindingConfidence.CONFIRMED,
                description=description,
                path=self.path,
                line=node.lineno,
                column=node.col_offset + 1,
                cwe=cwe,
            )
        )

    def _expression_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self._expression_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""

    def _uses_safe_yaml_loader(self, node: ast.Call) -> bool:
        for keyword in node.keywords:
            if keyword.arg != "Loader":
                continue
            loader_name = self._expression_name(keyword.value)
            if loader_name.endswith((".SafeLoader", ".CSafeLoader")):
                return True
        return False


def _is_dynamic_text(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return False
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return True
    return True


def _uses_literal_shell_true(node: ast.Call) -> bool:
    return _has_literal_keyword(node, "shell", True)


def _uses_literal_verify_false(node: ast.Call) -> bool:
    return _has_literal_keyword(node, "verify", False)


def _has_literal_keyword(node: ast.Call, name: str, expected: bool) -> bool:
    return any(
        keyword.arg == name
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is expected
        for keyword in node.keywords
    )


def _is_request_call(call_name: str) -> bool:
    return call_name.startswith("requests") and call_name.endswith(tuple(_REQUEST_CALL_SUFFIXES))
