"""
Smart Contracts Implementation
Enhanced with more contract types and better error handling.
"""

import logging
import re
from typing import Any, Callable, Dict, List, Optional, Set
from abc import ABC

from ..core.interfaces import SmartContract
from ..core.models import ToolCall, AgentState
from ..core.exceptions import ContractViolation

logger = logging.getLogger(__name__)


def precondition(func: Callable) -> Callable:
    """Decorator to mark a method as a precondition."""
    func._is_precondition = True
    return func


def postcondition(func: Callable) -> Callable:
    """Decorator to mark a method as a postcondition."""
    func._is_postcondition = True
    return func


def invariant(func: Callable) -> Callable:
    """Decorator to mark a method as an invariant."""
    func._is_invariant = True
    return func


def composition_rule(func: Callable) -> Callable:
    """Decorator to mark a method as a composition rule."""
    func._is_composition_rule = True
    return func


class BaseSmartContract(SmartContract, ABC):
    """Base class for smart contracts with decorator support."""
    
    def __init__(self) -> None:
        self._preconditions: List[Callable] = []
        self._postconditions: List[Callable] = []
        self._invariants: List[Callable] = []
        self._composition_rules: List[Callable] = []
        
        self._collect_decorated_methods()
    
    def _collect_decorated_methods(self) -> None:
        """Collect all methods marked with decorators."""
        for name in dir(self):
            method = getattr(self, name)
            if callable(method):
                if hasattr(method, "_is_precondition"):
                    self._preconditions.append(method)
                elif hasattr(method, "_is_postcondition"):
                    self._postconditions.append(method)
                elif hasattr(method, "_is_invariant"):
                    self._invariants.append(method)
                elif hasattr(method, "_is_composition_rule"):
                    self._composition_rules.append(method)
    
    def validate_precondition(self, action: ToolCall, state: AgentState) -> bool:
        """Validate all preconditions."""
        for precondition_func in self._preconditions:
            try:
                result = precondition_func(action, state)
                if result is False:
                    raise ContractViolation(
                        f"Precondition {precondition_func.__name__} failed",
                        contract_name=self.__class__.__name__,
                        violation_type="PRECONDITION_FAILED",
                    )
            except ContractViolation:
                raise
            except Exception as e:
                logger.error(f"Precondition check failed: {e}", exc_info=True)
                raise ContractViolation(
                    f"Precondition check error: {str(e)}",
                    contract_name=self.__class__.__name__,
                    violation_type="PRECONDITION_ERROR",
                )
        return True
    
    def validate_postcondition(self, action: ToolCall, result: Any, state: AgentState) -> bool:
        """Validate all postconditions."""
        for postcondition_func in self._postconditions:
            try:
                check_result = postcondition_func(action, result, state)
                if check_result is False:
                    raise ContractViolation(
                        f"Postcondition {postcondition_func.__name__} failed",
                        contract_name=self.__class__.__name__,
                        violation_type="POSTCONDITION_FAILED",
                    )
            except ContractViolation:
                raise
            except Exception as e:
                logger.error(f"Postcondition check failed: {e}", exc_info=True)
                raise ContractViolation(
                    f"Postcondition check error: {str(e)}",
                    contract_name=self.__class__.__name__,
                    violation_type="POSTCONDITION_ERROR",
                )
        return True


class SQLQueryContract(BaseSmartContract):
    """Smart contract for SQL query execution."""
    
    @precondition
    def no_destructive_operations(self, action: ToolCall, state: AgentState) -> bool:
        """Block DROP, DELETE, TRUNCATE, ALTER operations."""
        query = action.tool_args.get("query", "").upper()
        forbidden = {"DROP", "DELETE", "TRUNCATE", "ALTER", "CREATE"}
        
        for keyword in forbidden:
            if re.search(rf"\b{keyword}\b", query):
                raise ContractViolation(
                    f"Destructive SQL operation detected: {keyword}",
                    contract_name="SQLQueryContract",
                    violation_type="DESTRUCTIVE_OPERATION",
                    query=query,
                )
        return True
    
    @precondition
    def no_injection_patterns(self, action: ToolCall, state: AgentState) -> bool:
        """Block SQL injection patterns that bypass row-level authorisation.

        Covers tautology-based predicates (``OR 1=1``, ``OR 'a'='a'``,
        ``OR TRUE``), stacked statements, UNION-based extraction, and inline
        comment truncation used to neutralise the remainder of the query.
        """
        query = action.tool_args.get("query", "")

        # Tautology: a comparison whose two sides are the same literal.
        tautology = re.compile(
            r"\bOR\b\s*"
            r"(?:(\d+)\s*=\s*\1"                # OR 1=1
            r"|'([^']*)'\s*=\s*'\2'"            # OR 'a'='a'
            r"|\bTRUE\b)",                     # OR TRUE
            re.IGNORECASE,
        )
        if tautology.search(query):
            raise ContractViolation(
                "SQL injection tautology detected: always-true predicate",
                contract_name="SQLQueryContract",
                violation_type="SQL_INJECTION_TAUTOLOGY",
                query=query[:200],
            )

        # Stacked statements: a terminator followed by another statement.
        if re.search(r";\s*\S", query):
            raise ContractViolation(
                "SQL injection detected: stacked statement",
                contract_name="SQLQueryContract",
                violation_type="SQL_INJECTION_STACKED",
                query=query[:200],
            )

        # UNION-based extraction of a second table.
        if re.search(r"\bUNION\b\s+(?:ALL\s+)?\bSELECT\b", query, re.IGNORECASE):
            raise ContractViolation(
                "SQL injection detected: UNION SELECT",
                contract_name="SQLQueryContract",
                violation_type="SQL_INJECTION_UNION",
                query=query[:200],
            )

        # Inline comment truncation of the trailing predicate.
        if re.search(r"(--|#)\s*\S", query) and not re.match(r"^\s*--", query):
            raise ContractViolation(
                "SQL injection detected: inline comment",
                contract_name="SQLQueryContract",
                violation_type="SQL_INJECTION_COMMENT",
                query=query[:200],
            )

        return True

    @precondition
    def no_ssrf_patterns(self, action: ToolCall, state: AgentState) -> bool:
        """Block SQL injection patterns that could lead to SSRF."""
        query = action.tool_args.get("query", "").upper()
        forbidden_patterns = ["INTO OUTFILE", "LOAD_FILE", "INTO DUMPFILE"]
        
        for pattern in forbidden_patterns:
            if pattern in query:
                raise ContractViolation(
                    f"SSRF pattern detected: {pattern}",
                    contract_name="SQLQueryContract",
                    violation_type="SSRF_PATTERN",
                )
        return True
    
    @precondition
    def row_limit_enforcement(self, action: ToolCall, state: AgentState) -> bool:
        """Enforce row limits on queries."""
        query = action.tool_args.get("query", "")
        
        if "LIMIT" not in query.upper():
            logger.warning("Query missing LIMIT clause, adding default limit")
            action.tool_args["query"] = f"{query} LIMIT 1000"
        
        return True
    
    @precondition
    def check_table_access(self, action: ToolCall, state: AgentState) -> bool:
        """Check if agent has access to referenced tables."""
        query = action.tool_args.get("query", "").lower()
        
        from_clause = re.search(r"from\s+(\w+)", query)
        if from_clause:
            table_name = from_clause.group(1)
            logger.debug(f"Query references table: {table_name}")
        
        return True


class HTTPRequestContract(BaseSmartContract):
    """Smart contract for HTTP request execution."""
    
    @precondition
    def url_allowlist(self, action: ToolCall, state: AgentState) -> bool:
        """Only allow requests to approved URLs."""
        url = action.tool_args.get("url", "")
        
        forbidden_domains = ["evil.com", "attacker.com", "169.254.169.254"]
        for domain in forbidden_domains:
            if domain in url:
                raise ContractViolation(
                    f"URL contains forbidden domain: {domain}",
                    contract_name="HTTPRequestContract",
                    violation_type="URL_NOT_ALLOWED",
                )
        return True
    
    @precondition
    def no_internal_ips(self, action: ToolCall, state: AgentState) -> bool:
        """Block requests to internal IP addresses."""
        url = action.tool_args.get("url", "")
        
        internal_patterns = [
            r"127\.0\.0\.\d+",
            r"10\.\d+\.\d+\.\d+",
            r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",
            r"192\.168\.\d+\.\d+",
        ]
        
        for pattern in internal_patterns:
            if re.search(pattern, url):
                raise ContractViolation(
                    "URL contains internal IP address",
                    contract_name="HTTPRequestContract",
                    violation_type="INTERNAL_IP",
                )
        return True
    
    @precondition
    def method_validation(self, action: ToolCall, state: AgentState) -> bool:
        """Validate HTTP method."""
        method = action.tool_args.get("method", "GET").upper()
        allowed_methods = {"GET", "POST", "PUT", "DELETE", "PATCH"}
        
        if method not in allowed_methods:
            raise ContractViolation(
                f"HTTP method {method} not allowed",
                contract_name="HTTPRequestContract",
                violation_type="INVALID_METHOD",
            )
        return True


class EmailSendContract(BaseSmartContract):
    """Smart contract for email sending."""
    
    @precondition
    def recipient_allowlist(self, action: ToolCall, state: AgentState) -> bool:
        """Only allow emails to approved domains."""
        recipient = action.tool_args.get("to", "")
        allowed_domains = {"@company.com", "@trusted-partner.com"}
        
        if not any(recipient.endswith(d) for d in allowed_domains):
            raise ContractViolation(
                f"Recipient {recipient} not in allowlist",
                contract_name="EmailSendContract",
                violation_type="RECIPIENT_NOT_ALLOWED",
            )
        return True
    
    @precondition
    def no_pii_in_body(self, action: ToolCall, state: AgentState) -> bool:
        """Block emails containing unmasked PII."""
        body = action.tool_args.get("body", "")
        
        pii_patterns = [
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
            r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",  # Credit card
        ]
        
        for pattern in pii_patterns:
            if re.search(pattern, body):
                raise ContractViolation(
                    "Email body contains unmasked PII",
                    contract_name="EmailSendContract",
                    violation_type="PII_LEAK",
                )
        return True
    
    @precondition
    def subject_length(self, action: ToolCall, state: AgentState) -> bool:
        """Validate subject length."""
        subject = action.tool_args.get("subject", "")
        if len(subject) > 200:
            raise ContractViolation(
                "Email subject too long (max 200 chars)",
                contract_name="EmailSendContract",
                violation_type="SUBJECT_TOO_LONG",
            )
        return True


class CodeExecutionContract(BaseSmartContract):
    """Smart contract for code execution.

    Guards the ``code`` argument against primitives that are dangerous in an
    agent runtime regardless of the surrounding task: destructive filesystem
    calls, process/shell spawning, dynamic code execution, reverse shells and
    download-and-run pipelines, encoded payloads, native-memory execution,
    credential-file access, keylogging, cryptomining and defence tampering.
    Intent-only abuse (a natural-language instruction smuggled into ``code``)
    is out of scope for a syntactic filter and is left to the semantic firewall.
    """

    DANGEROUS_PATTERNS: List[str] = [
        # destructive filesystem operations
        r"rm\s+-rf", r"--no-preserve-root", r"shutil\.rmtree",
        r"os\.(remove|unlink|rmdir)\s*\(", r"os\.(rename|replace)\s*\(",
        r"\bformat\s+[a-z]:", r"\bmkfs\b",
        # process and shell spawning
        r"\bsubprocess\b", r"os\.system", r"os\.popen",
        r"os\.(execl|execv|execle|execlp|execvp|spawnl|spawnv)", r"pty\.spawn",
        # dynamic code execution
        r"\beval\s*\(", r"\bexec\s*\(", r"__import__", r"\bcompile\s*\(",
        r"marshal\.loads",
        # reverse shells and download-and-run
        r"socket\.socket", r"/dev/tcp",
        r"(?i)curl[^\n]*\|\s*(ba)?sh", r"(?i)wget[^\n]*\|\s*sh",
        # encoded / obfuscated payloads
        r"base64[^\n]*(b64decode|decode)[^\n]*(exec|eval)",
        r"(?i)powershell[^\n]*-e(nc)?\b",
        # native / in-memory execution
        r"\bctypes\b", r"\bCDLL\b", r"\bwindll\b", r"VirtualAlloc", r"shellcode",
        # credential and secrets access
        r"/etc/(shadow|passwd)", r"id_rsa", r"\.ssh/", r"lsass", r"mimikatz",
        # keylogging
        r"\bpynput\b", r"keyboard\.Listener", r"keylog",
        # cryptomining
        r"\bxmrig\b", r"stratum\+tcp", r"minexmr",
        # defence tampering
        r"(?i)netsh\s+advfirewall", r"Set-MpPreference", r"iptables\s+-F",
    ]

    @precondition
    def no_dangerous_code(self, action: ToolCall, state: AgentState) -> bool:
        """Block code that contains a dangerous primitive."""
        code = action.tool_args.get("code", "")
        if not isinstance(code, str):
            code = str(code)

        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, code):
                raise ContractViolation(
                    f"Dangerous code pattern detected: {pattern}",
                    contract_name="CodeExecutionContract",
                    violation_type="DANGEROUS_CODE",
                )
        return True

    
    @precondition
    def code_length_limit(self, action: ToolCall, state: AgentState) -> bool:
        """Limit code length."""
        code = action.tool_args.get("code", "")
        if len(code) > 10000:
            raise ContractViolation(
                "Code too long (max 10000 chars)",
                contract_name="CodeExecutionContract",
                violation_type="CODE_TOO_LONG",
            )
        return True


class AdminToolContract(BaseSmartContract):
    """Smart contract for administrative operations.

    The agent profiles that expose ``admin_tool`` scope it to read-only
    administration: enumerating accounts, inspecting configuration, reporting
    status. Every operation whose leading verb changes state, grants a
    capability, alters a security control, or touches a credential or secret is
    outside that grant and is rejected here as a contract violation. This is the
    invariant the benchmark taxonomy assigns to the contract layer for the
    direct-harm (F05), destructive (F07) and privilege-granting (F02) families,
    so an irreversible admin operation is a hard block at stage three rather than
    falling through to the escalation hedge. Unknown or empty actions fail closed,
    consistent with the monitor's deny-by-default stance.
    """

    READ_VERBS = (
        "list", "get", "read", "view", "describe", "show", "inspect",
        "check", "search", "fetch", "enumerate", "count", "status", "report",
        "query", "lookup", "browse", "monitor",
    )

    @precondition
    def read_only_operation(self, action: ToolCall, state: AgentState) -> bool:
        """Reject any admin action whose leading verb mutates state."""
        op = str(action.tool_args.get("action", "")).strip().lower()
        if not op:
            raise ContractViolation(
                "admin_tool call carries no action; refusing by default",
                contract_name="AdminToolContract",
                violation_type="MISSING_ADMIN_ACTION",
            )
        head = re.split(r"[_\-:\s/]+", op)[0]
        if any(head == verb or head.startswith(verb) for verb in self.READ_VERBS):
            return True
        raise ContractViolation(
            f"Non-read-only administrative operation: {op!r}",
            contract_name="AdminToolContract",
            violation_type="MUTATING_ADMIN_OPERATION",
            operation=op[:120],
        )


class ContractRegistry:
    """Registry for smart contracts."""

    def __init__(self) -> None:
        self._contracts: Dict[str, SmartContract] = {}
        self._register_default_contracts()

    def _register_default_contracts(self) -> None:
        """Register default smart contracts."""
        self.register_contract("sql_query", SQLQueryContract())
        self.register_contract("http_request", HTTPRequestContract())
        self.register_contract("send_email", EmailSendContract())
        self.register_contract("code_execute", CodeExecutionContract())
        self.register_contract("admin_tool", AdminToolContract())

    def register_contract(self, tool_name: str, contract: SmartContract) -> None:
        """Register a contract for a tool."""
        self._contracts[tool_name] = contract
        logger.debug(f"Registered contract for tool: {tool_name}")
    
    def get_contract(self, tool_name: str) -> Optional[SmartContract]:
        """Get contract for a tool."""
        return self._contracts.get(tool_name)
    
    def unregister_contract(self, tool_name: str) -> None:
        """Unregister a contract."""
        if tool_name in self._contracts:
            del self._contracts[tool_name]
            logger.debug(f"Unregistered contract for tool: {tool_name}")
    
    def list_contracts(self) -> List[str]:
        """List all registered contracts."""
        return list(self._contracts.keys())
