import json
from types import SimpleNamespace

from tests.ranking.report.tools import generate_metadata


def _write_source_tree(root):
    include = root / 'inc'
    include.mkdir(parents=True)
    (include / 'saiport.h').write_text(
        '''
typedef enum _sai_port_attr_t
{
    /**
     * @brief Administrative state
     * @type bool
     * @flags CREATE_AND_SET
     */
    SAI_PORT_ATTR_ADMIN_STATE,
} sai_port_attr_t;
''', encoding='utf-8')
    return include


def test_pipeline_generates_metadata_from_explicit_external_inputs(tmp_path):
    include = _write_source_tree(tmp_path / 'source')
    output = tmp_path / 'generated'
    generate_metadata.generate(SimpleNamespace(
        inc=include, experimental=[], out_dir=output))
    paths = generate_metadata.validate_metadata(output)
    assert set(paths) == set(generate_metadata.METADATA_FILES)
    skeleton = json.loads(paths['skeleton.json'].read_text())
    assert skeleton['denominator'] == len(skeleton['cells'])
    assert {cell['attr'] for cell in skeleton['cells']} == {
        'SAI_PORT_ATTR_ADMIN_STATE'}


def test_pipeline_output_is_stable_across_source_roots(tmp_path):
    outputs = []
    for name in ('first-root', 'unrelated-second-root'):
        include = _write_source_tree(tmp_path / name)
        output = tmp_path / ('output-' + name)
        generate_metadata.generate(SimpleNamespace(
            inc=include, experimental=[], out_dir=output))
        outputs.append(output)

    for name in generate_metadata.METADATA_FILES:
        assert (outputs[0] / name).read_bytes() == (
            outputs[1] / name).read_bytes()
    skeleton = json.loads((outputs[0] / 'skeleton.json').read_text())
    assert 'attr_dirs' not in skeleton
    assert 'enum_dirs' not in skeleton
    assert str(tmp_path) not in (outputs[0] / 'skeleton.json').read_text()
