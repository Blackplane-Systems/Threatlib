"""Operational policy utilities."""

__all__ = ["diff_policies", "lint_policy", "policy_hash", "policy_summary"]


def __getattr__(name):
    if name in __all__:
        from threatlib.policy.versioning import diff_policies, lint_policy, policy_hash, policy_summary

        return {
            "diff_policies": diff_policies,
            "lint_policy": lint_policy,
            "policy_hash": policy_hash,
            "policy_summary": policy_summary,
        }[name]
    raise AttributeError(name)
