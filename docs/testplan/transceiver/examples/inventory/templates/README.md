# Transceiver Template Files

This directory contains template files for validating attribute completeness during transceiver testing.

## deployment_templates.json

This file defines required and optional attributes for each deployment type. The validation process compares the actual attributes in `port_attributes_dict` against these templates to ensure comprehensive coverage.

### Structure

```json
{
  "deployment_templates": {
    "<DEPLOYMENT_NAME>": {
      "required_attributes": {
        "<CATEGORY>": ["attr1", "attr2"]
      },
      "optional_attributes": {
        "<CATEGORY>": ["attr1", "attr2"]
      }
    }
  }
}
```

### Usage

The framework automatically:

1. Extracts the `deployment` field from `BASE_ATTRIBUTES`
2. Loads the corresponding deployment template
3. Compares actual attributes against required/optional lists
4. Reports missing attributes with appropriate severity:
   - **ERROR**: Missing required attributes (test fails)
   - **WARNING**: Missing optional attributes (test continues)
   - **INFO**: Fully compliant (all attributes present)

### Example Template

See the test plan documentation for a complete example of `deployment_templates.json`.

### Configuration

- **File location**: `ansible/files/transceiver/inventory/templates/deployment_templates.json`
- **Validation control**: Use `--skip_transceiver_template_validation` pytest parameter to bypass validation
- **Default behavior**: Validation runs automatically if the template file exists

For more details, see the [Attribute Completeness Validation](../../test_plan.md#3-attribute-completeness-validation) section in the test plan.
