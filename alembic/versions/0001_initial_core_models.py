"""Initial migration creating all Sentinel core domain tables

Revision ID: 0001_initial_core_models
Revises:
Create Date: 2026-08-28 00:43:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '0001_initial_core_models'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. sentinel_targets
    op.create_table(
        'sentinel_targets',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('type', sa.String(length=32), nullable=False),
        sa.Column('value', sa.String(length=512), nullable=False),
        sa.Column('resolved_ips', sa.JSON(), nullable=False),
        sa.Column('parent_asset_id', sa.String(length=64), nullable=True),
        sa.Column('criticality', sa.String(length=32), nullable=False),
        sa.Column('environment', sa.String(length=32), nullable=False),
        sa.Column('owner', sa.String(length=128), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_sentinel_targets_id', 'sentinel_targets', ['id'])
    op.create_index('ix_sentinel_targets_type', 'sentinel_targets', ['type'])
    op.create_index('ix_sentinel_targets_value', 'sentinel_targets', ['value'])

    # 2. sentinel_targetsets
    op.create_table(
        'sentinel_targetsets',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('name', sa.String(length=256), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('context_notes', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_sentinel_targetsets_id', 'sentinel_targetsets', ['id'])

    # 3. sentinel_targetset_targets
    op.create_table(
        'sentinel_targetset_targets',
        sa.Column('targetset_id', sa.String(length=64), sa.ForeignKey('sentinel_targetsets.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('target_id', sa.String(length=64), sa.ForeignKey('sentinel_targets.id', ondelete='CASCADE'), primary_key=True),
    )

    # 4. sentinel_scopes
    op.create_table(
        'sentinel_scopes',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('name', sa.String(length=256), nullable=False),
        sa.Column('allowed_targets', sa.JSON(), nullable=False),
        sa.Column('in_scope_declarations', sa.JSON(), nullable=False),
        sa.Column('out_of_scope_declarations', sa.JSON(), nullable=False),
        sa.Column('environment', sa.String(length=32), nullable=False),
        sa.Column('authorization_type', sa.String(length=64), nullable=False),
        sa.Column('reference_ticket_id', sa.String(length=128), nullable=True),
        sa.Column('authorized_by', sa.String(length=128), nullable=True),
        sa.Column('expiry', sa.DateTime(timezone=True), nullable=True),
        sa.Column('max_intensity', sa.Float(), nullable=False),
        sa.Column('offensive_actions_enabled', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_sentinel_scopes_id', 'sentinel_scopes', ['id'])

    # 5. sentinel_policies
    op.create_table(
        'sentinel_policies',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('name', sa.String(length=256), nullable=False),
        sa.Column('allowed_module_classes', sa.JSON(), nullable=False),
        sa.Column('allowed_action_classes', sa.JSON(), nullable=False),
        sa.Column('rate_limit_rps', sa.Float(), nullable=False),
        sa.Column('max_intensity', sa.Float(), nullable=False),
        sa.Column('credential_handling_rules', sa.JSON(), nullable=False),
        sa.Column('require_approval_for_offensive', sa.Boolean(), nullable=False),
        sa.Column('kill_switch_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_sentinel_policies_id', 'sentinel_policies', ['id'])

    # 6. sentinel_tasks
    op.create_table(
        'sentinel_tasks',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('objective', sa.Text(), nullable=False),
        sa.Column('target_set_id', sa.String(length=64), sa.ForeignKey('sentinel_targetsets.id'), nullable=False),
        sa.Column('scope_id', sa.String(length=64), sa.ForeignKey('sentinel_scopes.id'), nullable=False),
        sa.Column('policy_id', sa.String(length=64), sa.ForeignKey('sentinel_policies.id'), nullable=False),
        sa.Column('mode', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('requested_output_type', sa.String(length=64), nullable=False),
        sa.Column('progress_percentage', sa.Float(), nullable=False),
        sa.Column('correlation_id', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_sentinel_tasks_id', 'sentinel_tasks', ['id'])
    op.create_index('ix_sentinel_tasks_status', 'sentinel_tasks', ['status'])
    op.create_index('ix_sentinel_tasks_correlation_id', 'sentinel_tasks', ['correlation_id'])

    # 7. sentinel_action_requests
    op.create_table(
        'sentinel_action_requests',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('task_id', sa.String(length=64), sa.ForeignKey('sentinel_tasks.id', ondelete='CASCADE'), nullable=False),
        sa.Column('agent', sa.String(length=128), nullable=False),
        sa.Column('action_type', sa.String(length=128), nullable=False),
        sa.Column('parameters', sa.JSON(), nullable=False),
        sa.Column('target_refs', sa.JSON(), nullable=False),
        sa.Column('expected_impact_level', sa.String(length=32), nullable=False),
        sa.Column('requires_approval', sa.Boolean(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_sentinel_action_requests_id', 'sentinel_action_requests', ['id'])
    op.create_index('ix_sentinel_action_requests_task_id', 'sentinel_action_requests', ['task_id'])
    op.create_index('ix_sentinel_action_requests_action_type', 'sentinel_action_requests', ['action_type'])
    op.create_index('ix_sentinel_action_requests_status', 'sentinel_action_requests', ['status'])

    # 8. sentinel_action_results
    op.create_table(
        'sentinel_action_results',
        sa.Column('action_id', sa.String(length=64), primary_key=True),
        sa.Column('task_id', sa.String(length=64), sa.ForeignKey('sentinel_tasks.id', ondelete='CASCADE'), nullable=False),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('output_summary', sa.Text(), nullable=False),
        sa.Column('raw_output_uri', sa.String(length=512), nullable=True),
        sa.Column('duration_seconds', sa.Float(), nullable=False),
        sa.Column('error_info', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_sentinel_action_results_action_id', 'sentinel_action_results', ['action_id'])
    op.create_index('ix_sentinel_action_results_task_id', 'sentinel_action_results', ['task_id'])

    # 9. sentinel_evidence
    op.create_table(
        'sentinel_evidence',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('task_id', sa.String(length=64), sa.ForeignKey('sentinel_tasks.id', ondelete='CASCADE'), nullable=False),
        sa.Column('target_ref', sa.String(length=512), nullable=False),
        sa.Column('source_agent', sa.String(length=128), nullable=False),
        sa.Column('source_module', sa.String(length=128), nullable=False),
        sa.Column('source_tool', sa.String(length=128), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('artifact_storage_key', sa.String(length=512), nullable=False),
        sa.Column('content_type', sa.String(length=128), nullable=False),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('integrity_metadata', sa.JSON(), nullable=False),
        sa.Column('collected_by', sa.String(length=128), nullable=False),
        sa.Column('chain_of_custody', sa.JSON(), nullable=False),
        sa.Column('context_metadata', sa.JSON(), nullable=False),
    )
    op.create_index('ix_sentinel_evidence_id', 'sentinel_evidence', ['id'])
    op.create_index('ix_sentinel_evidence_task_id', 'sentinel_evidence', ['task_id'])
    op.create_index('ix_sentinel_evidence_target_ref', 'sentinel_evidence', ['target_ref'])
    op.create_index('ix_sentinel_evidence_source_module', 'sentinel_evidence', ['source_module'])
    op.create_index('ix_sentinel_evidence_sha256_hash', 'sentinel_evidence', ['sha256_hash'])

    # 10. sentinel_findings
    op.create_table(
        'sentinel_findings',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('task_id', sa.String(length=64), sa.ForeignKey('sentinel_tasks.id', ondelete='CASCADE'), nullable=False),
        sa.Column('title', sa.String(length=512), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('target_ref', sa.String(length=512), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('exploitability_context', sa.Text(), nullable=True),
        sa.Column('impact', sa.Text(), nullable=True),
        sa.Column('evidence_refs', sa.JSON(), nullable=False),
        sa.Column('related_cves', sa.JSON(), nullable=False),
        sa.Column('related_cwes', sa.JSON(), nullable=False),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_sentinel_findings_id', 'sentinel_findings', ['id'])
    op.create_index('ix_sentinel_findings_task_id', 'sentinel_findings', ['task_id'])
    op.create_index('ix_sentinel_findings_target_ref', 'sentinel_findings', ['target_ref'])
    op.create_index('ix_sentinel_findings_severity', 'sentinel_findings', ['severity'])
    op.create_index('ix_sentinel_findings_status', 'sentinel_findings', ['status'])

    # 11. sentinel_risks
    op.create_table(
        'sentinel_risks',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('finding_id', sa.String(length=64), sa.ForeignKey('sentinel_findings.id', ondelete='CASCADE'), nullable=False),
        sa.Column('task_id', sa.String(length=64), sa.ForeignKey('sentinel_tasks.id', ondelete='CASCADE'), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('asset_criticality', sa.String(length=32), nullable=False),
        sa.Column('exposure_score', sa.Float(), nullable=False),
        sa.Column('exploitability_score', sa.Float(), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('computed_risk_score', sa.Float(), nullable=False),
        sa.Column('risk_tier', sa.String(length=32), nullable=False),
        sa.Column('rationale', sa.Text(), nullable=False),
    )
    op.create_index('ix_sentinel_risks_id', 'sentinel_risks', ['id'])
    op.create_index('ix_sentinel_risks_finding_id', 'sentinel_risks', ['finding_id'])
    op.create_index('ix_sentinel_risks_task_id', 'sentinel_risks', ['task_id'])
    op.create_index('ix_sentinel_risks_computed_risk_score', 'sentinel_risks', ['computed_risk_score'])
    op.create_index('ix_sentinel_risks_risk_tier', 'sentinel_risks', ['risk_tier'])

    # 12. sentinel_events
    op.create_table(
        'sentinel_events',
        sa.Column('event_id', sa.String(length=64), primary_key=True),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('topic', sa.String(length=128), nullable=False),
        sa.Column('source', sa.String(length=128), nullable=False),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.Column('correlation_id', sa.String(length=64), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_sentinel_events_event_id', 'sentinel_events', ['event_id'])
    op.create_index('ix_sentinel_events_event_type', 'sentinel_events', ['event_type'])
    op.create_index('ix_sentinel_events_topic', 'sentinel_events', ['topic'])
    op.create_index('ix_sentinel_events_correlation_id', 'sentinel_events', ['correlation_id'])

    # 13. sentinel_audit_logs
    op.create_table(
        'sentinel_audit_logs',
        sa.Column('entry_id', sa.String(length=64), primary_key=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('event_type', sa.String(length=128), nullable=False),
        sa.Column('actor', sa.String(length=128), nullable=False),
        sa.Column('target', sa.String(length=256), nullable=True),
        sa.Column('action_type', sa.String(length=128), nullable=False),
        sa.Column('scope_policy', sa.String(length=128), nullable=False),
        sa.Column('decision', sa.String(length=64), nullable=False),
        sa.Column('details', sa.JSON(), nullable=False),
        sa.Column('previous_hash', sa.String(length=128), nullable=False),
        sa.Column('current_hash', sa.String(length=128), nullable=False),
        sa.Column('signature', sa.String(length=256), nullable=False),
        sa.Column('verified', sa.Boolean(), nullable=False),
    )
    op.create_index('ix_sentinel_audit_logs_entry_id', 'sentinel_audit_logs', ['entry_id'])
    op.create_index('ix_sentinel_audit_logs_event_type', 'sentinel_audit_logs', ['event_type'])
    op.create_index('ix_sentinel_audit_logs_actor', 'sentinel_audit_logs', ['actor'])
    op.create_index('ix_sentinel_audit_logs_action_type', 'sentinel_audit_logs', ['action_type'])
    op.create_index('ix_sentinel_audit_logs_decision', 'sentinel_audit_logs', ['decision'])


def downgrade() -> None:
    op.drop_table('sentinel_audit_logs')
    op.drop_table('sentinel_events')
    op.drop_table('sentinel_risks')
    op.drop_table('sentinel_findings')
    op.drop_table('sentinel_evidence')
    op.drop_table('sentinel_action_results')
    op.drop_table('sentinel_action_requests')
    op.drop_table('sentinel_tasks')
    op.drop_table('sentinel_policies')
    op.drop_table('sentinel_scopes')
    op.drop_table('sentinel_targetset_targets')
    op.drop_table('sentinel_targetsets')
    op.drop_table('sentinel_targets')
