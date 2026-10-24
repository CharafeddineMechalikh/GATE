"""Tests for smart contracts."""

import pytest
from gate.core.models import ToolCall, AgentState
from gate.core.exceptions import ContractViolation
from gate.security.smart_contracts import SQLQueryContract, HTTPRequestContract


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
