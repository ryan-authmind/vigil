"""AuthMind integration descriptor — source of truth for registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

AUTHMIND = register_descriptor(
    IntegrationDescriptor(
        id="authmind",
        category="Identity & Access",
        mcp_server_names=("authmind",),
        fields=(
            IntegrationField("base_url"),
            IntegrationField("api_token", secret=True),
            IntegrationField("verify_ssl", value_type="bool"),
            # "polling" | "skills" | "both". Governs two independent gates:
            # AuthMindAdapter.is_configured() (federation polling) and the
            # authmind MCP server's handle_call_tool (skill enrichment). See
            # core.integrations.authmind.client.get_authmind_mode().
            IntegrationField("mode"),
        ),
    )
)
