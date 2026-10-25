"""Tests for smart contracts."""

import pytest
from gate.core.models import ToolCall, AgentState
from gate.core.exceptions import ContractViolation
from gate.security.smart_contracts import (
    SQLQueryContract,
    HTTPRequestContract,
    EmailSendContract,
    CodeExecutionContract,
    ContractRegistry,
    BaseSmartContract,
    precondition,
    postcondition,
    invariant,
    composition_rule,
)


class TestSQLQueryContract:
    """Tests for SQL query contract."""
    
    def setup_method(self):
        self.contract = SQLQueryContract()
        self.state = AgentState(agent_id="test-agent")
    
    def test_allows_select_query(self):
        action = ToolCall(
            tool_name="sql_query",
            tool_args={"query": "SELECT * FROM users LIMIT 10"},
            call_id="test-1",
        )
        assert self.contract.validate_precondition(action, self.state) is True
    
    def test_blocks_drop_query(self):
        action = ToolCall(
            tool_name="sql_query",
            tool_args={"query": "DROP TABLE users"},
            call_id="test-2",
        )
        with pytest.raises(ContractViolation) as exc_info:
            self.contract.validate_precondition(action, self.state)
        assert "DESTRUCTIVE_OPERATION" in str(exc_info.value)
    
    def test_blocks_delete_query(self):
        action = ToolCall(
            tool_name="sql_query",
            tool_args={"query": "DELETE FROM users WHERE id=1"},
            call_id="test-3",
        )
        with pytest.raises(ContractViolation):
            self.contract.validate_precondition(action, self.state)
    
    def test_blocks_ssrf_pattern(self):
        action = ToolCall(
            tool_name="sql_query",
            tool_args={"query": "SELECT * FROM users INTO OUTFILE '/tmp/data'"},
            call_id="test-4",
        )
        with pytest.raises(ContractViolation) as exc_info:
            self.contract.validate_precondition(action, self.state)
        assert "SSRF_PATTERN" in str(exc_info.value)
    
    def test_adds_limit_if_missing(self):
        action = ToolCall(
            tool_name="sql_query",
            tool_args={"query": "SELECT * FROM users"},
            call_id="test-5",
        )
        self.contract.validate_precondition(action, self.state)
        assert "LIMIT 1000" in action.tool_args["query"]


class TestHTTPRequestContract:
    """Tests for HTTP request contract."""
    
    def setup_method(self):
        self.contract = HTTPRequestContract()
        self.state = AgentState(agent_id="test-agent")
    
    def test_allows_external_url(self):
        action = ToolCall(
            tool_name="http_request",
            tool_args={"url": "https://api.example.com/data"},
            call_id="test-1",
        )
        assert self.contract.validate_precondition(action, self.state) is True
    
    def test_blocks_evil_domain(self):
        action = ToolCall(
            tool_name="http_request",
            tool_args={"url": "https://evil.com/malware"},
            call_id="test-2",
        )
        with pytest.raises(ContractViolation) as exc_info:
            self.contract.validate_precondition(action, self.state)
        assert "URL_NOT_ALLOWED" in str(exc_info.value)
    
    def test_blocks_internal_ip(self):
        action = ToolCall(
            tool_name="http_request",
            tool_args={"url": "http://192.168.1.1/admin"},
            call_id="test-3",
        )
        with pytest.raises(ContractViolation) as exc_info:
            self.contract.validate_precondition(action, self.state)
        assert "INTERNAL_IP" in str(exc_info.value)
    
    def test_blocks_aws_metadata(self):
        action = ToolCall(
            tool_name="http_request",
            tool_args={"url": "http://169.254.169.254/latest/meta-data/"},
            call_id="test-4",
        )
        with pytest.raises(ContractViolation):
            self.contract.validate_precondition(action, self.state)

    def test_blocks_invalid_method(self):
        action = ToolCall(
            tool_name="http_request",
            tool_args={"url": "https://api.example.com", "method": "TRACE"},
            call_id="test-5",
        )
        with pytest.raises(ContractViolation) as exc_info:
            self.contract.validate_precondition(action, self.state)
        assert "INVALID_METHOD" in str(exc_info.value)

    def test_allows_valid_method(self):
        action = ToolCall(
            tool_name="http_request",
            tool_args={"url": "https://api.example.com", "method": "post"},
            call_id="test-6",
        )
        assert self.contract.validate_precondition(action, self.state) is True


class TestSQLInjectionPatterns:
    def setup_method(self):
        self.contract = SQLQueryContract()
        self.state = AgentState(agent_id="test-agent")

    def _run(self, query):
        action = ToolCall(tool_name="sql_query",
                          tool_args={"query": query}, call_id="inj")
        return self.contract.validate_precondition(action, self.state)

    def test_blocks_numeric_tautology(self):
        with pytest.raises(ContractViolation) as exc_info:
            self._run("SELECT * FROM users WHERE id = 5 OR 1 = 1 LIMIT 10")
        assert "SQL_INJECTION_TAUTOLOGY" in str(exc_info.value)

    def test_blocks_string_tautology(self):
        with pytest.raises(ContractViolation) as exc_info:
            self._run("SELECT * FROM users WHERE name = 'x' OR 'a' = 'a' LIMIT 10")
        assert "SQL_INJECTION_TAUTOLOGY" in str(exc_info.value)

    def test_blocks_true_tautology(self):
        with pytest.raises(ContractViolation) as exc_info:
            self._run("SELECT * FROM users WHERE id = 1 OR TRUE LIMIT 10")
        assert "SQL_INJECTION_TAUTOLOGY" in str(exc_info.value)

    def test_blocks_stacked_statement(self):
        with pytest.raises(ContractViolation) as exc_info:
            self._run("SELECT * FROM users; DROP TABLE x LIMIT 10")
        assert str(exc_info.value.details["type"]) in {
            "DESTRUCTIVE_OPERATION", "SQL_INJECTION_STACKED"}

    def test_blocks_stacked_without_destructive(self):
        with pytest.raises(ContractViolation) as exc_info:
            self._run("SELECT a FROM t; SELECT b FROM u LIMIT 10")
        assert "SQL_INJECTION_STACKED" in str(exc_info.value)

    def test_blocks_union_select(self):
        with pytest.raises(ContractViolation) as exc_info:
            self._run("SELECT a FROM t UNION SELECT b FROM secrets LIMIT 10")
        assert "SQL_INJECTION_UNION" in str(exc_info.value)

    def test_blocks_union_all_select(self):
        with pytest.raises(ContractViolation) as exc_info:
            self._run("SELECT a FROM t UNION ALL SELECT b FROM u LIMIT 10")
        assert "SQL_INJECTION_UNION" in str(exc_info.value)

    def test_blocks_inline_comment(self):
        with pytest.raises(ContractViolation) as exc_info:
            self._run("SELECT * FROM t WHERE a = 1 -- remove predicate LIMIT 10")
        assert "SQL_INJECTION_COMMENT" in str(exc_info.value)

    def test_allows_leading_comment_only(self):
        # A query that *starts* with -- is not an inline-truncation attack.
        self._run("-- note\nSELECT a FROM t LIMIT 10")

    def test_clean_query_passes(self):
        assert self._run("SELECT name FROM users WHERE id = 3 LIMIT 10") is True


class TestEmailSendContract:
    def setup_method(self):
        self.contract = EmailSendContract()
        self.state = AgentState(agent_id="test-agent")

    def _run(self, **args):
        action = ToolCall(tool_name="send_email", tool_args=args, call_id="mail")
        return self.contract.validate_precondition(action, self.state)

    def test_allows_approved_domain(self):
        assert self._run(to="boss@company.com", body="hi", subject="s") is True

    def test_blocks_unknown_recipient(self):
        with pytest.raises(ContractViolation) as exc_info:
            self._run(to="someone@spam.com", body="hi", subject="s")
        assert "RECIPIENT_NOT_ALLOWED" in str(exc_info.value)

    def test_blocks_ssn_in_body(self):
        with pytest.raises(ContractViolation) as exc_info:
            self._run(to="a@company.com", body="my ssn 123-45-6789 ok", subject="s")
        assert "PII_LEAK" in str(exc_info.value)

    def test_blocks_credit_card_in_body(self):
        with pytest.raises(ContractViolation) as exc_info:
            self._run(to="a@company.com", body="card 4111-1111-1111-1111", subject="s")
        assert "PII_LEAK" in str(exc_info.value)

    def test_blocks_long_subject(self):
        with pytest.raises(ContractViolation) as exc_info:
            self._run(to="a@company.com", body="hi", subject="x" * 201)
        assert "SUBJECT_TOO_LONG" in str(exc_info.value)


class TestCodeExecutionContract:
    def setup_method(self):
        self.contract = CodeExecutionContract()
        self.state = AgentState(agent_id="test-agent")

    def _run(self, code):
        action = ToolCall(tool_name="code_execute", tool_args={"code": code},
                          call_id="exec")
        return self.contract.validate_precondition(action, self.state)

    def test_allows_safe_code(self):
        assert self._run("x = 1 + 2\nprint(x)") is True

    def test_blocks_dangerous_import(self):
        with pytest.raises(ContractViolation) as exc_info:
            self._run("import subprocess; subprocess.run(['ls'])")
        assert "DANGEROUS_CODE" in str(exc_info.value)

    def test_blocks_eval(self):
        with pytest.raises(ContractViolation) as exc_info:
            self._run("eval('1+1')")
        assert "DANGEROUS_CODE" in str(exc_info.value)

    def test_blocks_overlong_code(self):
        with pytest.raises(ContractViolation) as exc_info:
            self._run("a" * 10001)
        assert "CODE_TOO_LONG" in str(exc_info.value)


class TestContractRegistry:
    def test_default_contracts_registered(self):
        reg = ContractRegistry()
        for name in ("sql_query", "http_request", "send_email", "code_execute"):
            assert reg.get_contract(name) is not None
        assert set(reg.list_contracts()) >= {
            "sql_query", "http_request", "send_email", "code_execute"}

    def test_get_contract_unknown(self):
        reg = ContractRegistry()
        assert reg.get_contract("nope") is None

    def test_register_custom(self):
        reg = ContractRegistry()
        custom = SQLQueryContract()
        reg.register_contract("my_tool", custom)
        assert reg.get_contract("my_tool") is custom

    def test_unregister(self):
        reg = ContractRegistry()
        reg.unregister_contract("sql_query")
        assert reg.get_contract("sql_query") is None

    def test_unregister_missing_is_noop(self):
        reg = ContractRegistry()
        reg.unregister_contract("not_there")  # should not raise


# ---------------------------------------------------------------------------
# Base-class decorator collection and error handling
# ---------------------------------------------------------------------------

class _PostConditionContract(BaseSmartContract):
    @postcondition
    def result_present(self, action, result, state):
        return result is not None

    @invariant
    def always(self, state):
        return True

    @composition_rule
    def rule(self, a, b):
        return True


class _PreconditionFailsContract(BaseSmartContract):
    @precondition
    def bad(self, action, state):
        return False


class _PreconditionErrorsContract(BaseSmartContract):
    @precondition
    def boom(self, action, state):
        raise ValueError("kaboom")


class _PostconditionFailsContract(BaseSmartContract):
    @postcondition
    def p(self, action, result, state):
        return False


class _PostconditionErrorsContract(BaseSmartContract):
    @postcondition
    def p(self, action, result, state):
        raise RuntimeError("post boom")


class TestBaseSmartContract:
    def setup_method(self):
        self.state = AgentState(agent_id="test-agent")

    def test_decorated_methods_collected(self):
        c = _PostConditionContract()
        assert len(c._postconditions) == 1
        assert len(c._invariants) == 1
        assert len(c._composition_rules) == 1

    def test_postcondition_passes(self):
        c = _PostConditionContract()
        action = ToolCall(tool_name="t", tool_args={}, call_id="1")
        assert c.validate_postcondition(action, "ok", self.state) is True

    def test_precondition_false_raises_failed(self):
        c = _PreconditionFailsContract()
        action = ToolCall(tool_name="t", tool_args={}, call_id="1")
        with pytest.raises(ContractViolation) as exc_info:
            c.validate_precondition(action, self.state)
        assert exc_info.value.violation_type == "PRECONDITION_FAILED"

    def test_precondition_exception_raises_error(self):
        c = _PreconditionErrorsContract()
        action = ToolCall(tool_name="t", tool_args={}, call_id="1")
        with pytest.raises(ContractViolation) as exc_info:
            c.validate_precondition(action, self.state)
        assert exc_info.value.violation_type == "PRECONDITION_ERROR"

    def test_postcondition_false_raises_failed(self):
        c = _PostconditionFailsContract()
        action = ToolCall(tool_name="t", tool_args={}, call_id="1")
        with pytest.raises(ContractViolation) as exc_info:
            c.validate_postcondition(action, "x", self.state)
        assert exc_info.value.violation_type == "POSTCONDITION_FAILED"

    def test_postcondition_exception_raises_error(self):
        c = _PostconditionErrorsContract()
        action = ToolCall(tool_name="t", tool_args={}, call_id="1")
        with pytest.raises(ContractViolation) as exc_info:
            c.validate_postcondition(action, "x", self.state)
        assert exc_info.value.violation_type == "POSTCONDITION_ERROR"
