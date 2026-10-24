"""Integration tests for gate."""

import pytest
from gate import gateConfig, AgentProfile, ResourceBudget, DataScope
from gate.core.models import ToolCall, AgentState
from gate.core.monitor import gateMonitor
from gate.security.privilege_enforcer import DefaultPrivilegeEnforcer


class TestgateIntegration:
    """Integration tests for the full gate stack."""
    
    def setup_method(self):
        self.config = gateConfig(
            agent_profile=AgentProfile(
                agent_id="test-agent",
                role="tester",
                allowed_tools={"search", "query"},
                forbidden_tools={"send_email", "code_execute"},
                data_scope=DataScope(
                    allowed_databases={"test_db"},
                    forbidden_patterns={"169.254.169.254"},
                ),
                resource_budget=ResourceBudget(max_steps=10, max_cost_usd=1.0),
            ),
            enabled_checks={"privilege"},
        )
        
        self.monitor = gateMonitor(config=self.config)
        
        enforcer = DefaultPrivilegeEnforcer()
        enforcer.register_profile(self.config.agent_profile)
        self.monitor.privilege_enforcer = enforcer
    
    @pytest.mark.asyncio
    async def test_allows_permitted_tool(self):
        action = ToolCall(
            tool_name="search",
            tool_args={"query": "test"},
            call_id="test-1",
        )
        state = AgentState(agent_id="test-agent")
        
        result = await self.monitor.validate_action(action, state)
        assert result.is_allowed is True
    
    @pytest.mark.asyncio
    async def test_blocks_forbidden_tool(self):
        action = ToolCall(
            tool_name="send_email",
            tool_args={"to": "user@example.com"},
            call_id="test-2",
        )
        state = AgentState(agent_id="test-agent")
        
        result = await self.monitor.validate_action(action, state)
        assert result.is_allowed is False
        assert "Privilege violation" in result.reason
    
    @pytest.mark.asyncio
    async def test_blocks_unauthorized_data_access(self):
        action = ToolCall(
            tool_name="query",
            tool_args={"resource": "forbidden_db.users"},
            call_id="test-3",
        )
        state = AgentState(agent_id="test-agent")
        
        result = await self.monitor.validate_action(action, state)
        assert result.is_allowed is False
    
    @pytest.mark.asyncio
    async def test_blocks_ssrf_attempt(self):
        action = ToolCall(
            tool_name="query",
            tool_args={"url": "http://169.254.169.254/metadata"},
            call_id="test-4",
        )
        state = AgentState(agent_id="test-agent")
        
        result = await self.monitor.validate_action(action, state)
        assert result.is_allowed is False
    
    @pytest.mark.asyncio
    async def test_tracks_checks_passed(self):
        action = ToolCall(
            tool_name="search",
            tool_args={"query": "test"},
            call_id="test-5",
        )
        state = AgentState(agent_id="test-agent")
        
        result = await self.monitor.validate_action(action, state)
        assert "privilege" in result.checks_passed
