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
        ),
    )
)
