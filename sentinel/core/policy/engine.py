"""Sentinel Scope & Policy Validation Engine."""

import ipaddress

from sentinel.config.settings import get_settings
from sentinel.contracts.schemas.core import ActionRequest, ScopeDefinition


class PolicyDecision:
    def __init__(self, allowed: bool, reason: str, requires_approval: bool = False):
        self.allowed = allowed
        self.reason = reason
        self.requires_approval = requires_approval


class ScopePolicyEngine:
    """Enforces allowlists, target boundaries, offensive gates, and intensity limits."""

    def __init__(self, scope: ScopeDefinition):
        self.scope = scope
        self.settings = get_settings()

    def evaluate_action(self, action: ActionRequest) -> PolicyDecision:
        # Check Global Kill Switch
        if self.settings.kill_switch_active:
            return PolicyDecision(False, "Action blocked by Global Kill Switch.")

        # Check Target Scope Allowlists & Exclusions
        target_val = action.target.identifier
        if target_val in self.scope.excluded_targets:
            return PolicyDecision(False, f"Target {target_val} is explicitly excluded in scope.")

        # If allowed_targets is defined, ensure target is in scope
        if self.scope.allowed_targets and target_val not in self.scope.allowed_targets:
            # Check for subnet containment
            matched = False
            for allowed in self.scope.allowed_targets:
                if "/" in allowed:
                    try:
                        net = ipaddress.ip_network(allowed, strict=False)
                        ip = ipaddress.ip_address(target_val)
                        if ip in net:
                            matched = True
                            break
                    except ValueError:
                        pass
                elif allowed.startswith("*."):
                    suffix = allowed[1:]
                    if target_val.endswith(suffix):
                        matched = True
                        break

            if not matched:
                return PolicyDecision(False, f"Target {target_val} is outside authorized scope definition.")

        # Check Offensive Action Boundary
        if action.is_offensive:
            if not self.scope.offensive_actions_enabled:
                return PolicyDecision(False, "Offensive capabilities are disabled for this scope.")
            if not action.target.authorized:
                return PolicyDecision(False, "Target is not verified as owned/authorized for offensive action.")
            if self.settings.require_human_approval_for_offensive:
                return PolicyDecision(True, "Offensive action requires explicit operator approval.", requires_approval=True)

        # Check Intensity Limits
        if action.intensity > self.scope.max_intensity:
            return PolicyDecision(False, f"Action intensity {action.intensity} exceeds max allowed ({self.scope.max_intensity}).")

        # Check Module Allowlist
        if self.scope.allowed_modules and action.module_name not in self.scope.allowed_modules:
            return PolicyDecision(False, f"Module {action.module_name} is not permitted in this scope.")

        return PolicyDecision(True, "Action evaluated and permitted by policy.")
