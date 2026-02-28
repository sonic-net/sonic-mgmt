"""Deployment template based attribute completeness validation.

Template file path (relative to repo root):
    ansible/files/transceiver/inventory/templates/deployment_templates.json

Schema (minimal):
    {
      "deployment_templates": {
          "DEPLOYMENT_NAME": {
              "required_attributes": { "CATEGORY_KEY": ["field", ...], ...},
              "optional_attributes": { "CATEGORY_KEY": ["field", ...], ...}
          }
      }
    }

Behavior:
    * For each port, find its BASE_ATTRIBUTES.deployment and compare against the template.
    * Required attributes missing -> port FAIL (overall validation raises TemplateValidationError).
    * Optional attributes missing -> port PARTIAL.
    * All required + optional present -> port FULLY_COMPLIANT.
    * Ports whose deployment has no corresponding template are skipped (not counted in result list).

Return structure:
    {
       'results': [
           {
               'port': ..., 'deployment': ..., 'status': ...,
               'missing_required': [...], 'missing_optional': [...]
           }, ...
       ],
       'fully_compliant_ports': <int>,
       'total_ports': <int>,              # total ports provided (even those skipped)
       'compliance_percent': <float>,     # fully_compliant_ports / total_ports * 100
    }
"""

import json
import os
import logging

from .exceptions import TemplateValidationError
from .paths import REL_DEPLOYMENT_TEMPLATES_FILE

logger = logging.getLogger(__name__)


STATUS_FULLY = "FULLY_COMPLIANT"
STATUS_PARTIAL = "PARTIAL"
STATUS_FAIL = "FAIL"


class ComplianceResult(object):
    """Container for port compliance validation results."""
    def __init__(self, port, deployment, status, missing_required, missing_optional):
        self.port = port
        self.deployment = deployment
        self.status = status  # One of STATUS_FULLY | STATUS_PARTIAL | STATUS_FAIL
        self.missing_required = missing_required
        self.missing_optional = missing_optional

    def to_dict(self):
        return {
            'port': self.port,
            'deployment': self.deployment,
            'status': self.status,
            'missing_required': self.missing_required,
            'missing_optional': self.missing_optional,
        }


class TemplateValidator(object):
    def __init__(self, repo_root):
        """Initialize template validator.

        Always raises TemplateValidationError when required attributes are missing.
        Args:
            repo_root: Path to repository root containing the templates file.
        """
        self.repo_root = repo_root
        self._templates = None

    def _load_templates(self):
        if self._templates is not None:
            return self._templates
        path = os.path.join(self.repo_root, REL_DEPLOYMENT_TEMPLATES_FILE)
        if not os.path.isfile(path):
            logger.info(f"Template file {path} not found; skipping validation")
            self._templates = {}
            return self._templates
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self._templates = data.get('deployment_templates', {})
        return self._templates

    def validate(self, port_attributes_dict):
        templates = self._load_templates()
        if not templates:
            return {
                'results': [],
                'fully_compliant_ports': 0,
                'total_ports': len(port_attributes_dict),
                'compliance_percent': 0 if not port_attributes_dict else 100,
            }

        results = []
        fully_compliant_count = 0
        for port, port_data in port_attributes_dict.items():
            base_attrs = port_data.get('BASE_ATTRIBUTES', {})
            deployment = base_attrs.get('deployment')
            if not deployment or deployment not in templates:
                logger.info(f"No template for port {port} deployment {deployment}")
                continue
            template = templates[deployment]
            required_attrs = template.get('required_attributes', {})
            optional_attrs = template.get('optional_attributes', {})

            missing_required = []
            missing_optional = []

            def _check_category_fields(category_key, field_names, target_list):
                category_dict = port_data.get(category_key, {})
                for field in field_names:
                    if field not in category_dict:
                        target_list.append(f"{category_key}.{field}")

            for category_key, field_names in required_attrs.items():
                _check_category_fields(category_key, field_names, missing_required)
            for category_key, field_names in optional_attrs.items():
                _check_category_fields(category_key, field_names, missing_optional)

            if missing_required:
                status = STATUS_FAIL
            elif missing_optional:
                status = STATUS_PARTIAL
            else:
                status = STATUS_FULLY
                fully_compliant_count += 1

            results.append(ComplianceResult(
                port=port,
                deployment=deployment,
                status=status,
                missing_required=missing_required,
                missing_optional=missing_optional,
            ))

        total_ports = len(port_attributes_dict)
        compliance_percent = (fully_compliant_count / total_ports * 100) if total_ports else 0

        # Logging summary
        for result in results:
            if result.status == STATUS_FULLY:
                logger.info(f"PASS: {result.port} ({result.deployment}) - {result.status}")
            elif result.status == STATUS_PARTIAL:
                logger.warning(f"PARTIAL: {result.port} missing optional: {', '.join(result.missing_optional)}")
            else:
                logger.error(f"FAIL: {result.port} missing required: {', '.join(result.missing_required)}")

        logger.info(
            f"Overall Compliance: {compliance_percent:.1f}% "
            f"({fully_compliant_count}/{total_ports} ports fully compliant)"
        )

        if any(result.missing_required for result in results):
            missing_summary = {result.port: result.missing_required for result in results if result.missing_required}
            raise TemplateValidationError(f"Missing required attributes: {missing_summary}")

        return {
            'results': [result.to_dict() for result in results],
            'fully_compliant_ports': fully_compliant_count,
            'total_ports': total_ports,
            'compliance_percent': compliance_percent,
        }
