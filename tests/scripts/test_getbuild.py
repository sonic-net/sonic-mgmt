import contextlib
import io
import unittest
from unittest import mock

import getbuild


ARTIFACT_URL = 'https://dev.azure.com/example/artifacts?format=zip'


class GetBuildSecureBootTest(unittest.TestCase):
    def test_image_selection_preserves_the_local_staging_filename(self):
        """Select UEFI only when requested, retaining the existing local image name."""
        for secure_boot, remote_filename in (
            (False, 'sonic-vs.img.gz'),
            (True, 'sonic-vs.img-uefi.img.gz'),
        ):
            with self.subTest(secure_boot=secure_boot), \
                    mock.patch.object(getbuild, 'validate_url_or_abort'), \
                    mock.patch.object(getbuild, 'install_opener'), \
                    mock.patch.object(getbuild, 'urlretrieve') as retrieve:
                getbuild.download_artifacts(
                    ARTIFACT_URL, 'image', 'vs', 123, 1, '', '', secure_boot=secure_boot
                )
                retrieve.assert_called_once_with(
                    ARTIFACT_URL.replace('zip', 'file') + '&subPath=%2Ftarget%2F' + remote_filename,
                    'sonic-vs.img.gz',
                    getbuild.reporthook,
                )

    def test_secure_boot_downloads_firmware_from_the_same_build(self):
        """Request mandatory firmware from the image's build, independent of pipeline ID."""
        with mock.patch('sys.argv', [
            'getbuild.py', '--platform', 'vs', '--buildid', '123',
            '--build_pipeline_id', '1', '--secure-boot',
        ]), mock.patch.object(getbuild, 'get_download_url', return_value=(ARTIFACT_URL, 10)), \
                mock.patch.object(getbuild, 'download_artifacts') as image, \
                mock.patch.object(getbuild, 'download_secure_boot_firmware') as firmware, \
                mock.patch.object(getbuild.os.path, 'isdir', return_value=True):
            getbuild.main()
            image.assert_called_once_with(
                ARTIFACT_URL, 'image', 'vs', 123, 1, access_token='', token='', secure_boot=True,
            )
            firmware.assert_called_once_with(
                ARTIFACT_URL, 'sonic-vs_vars.fd', 'sonic-vm/images/sonic-vs_vars.fd', 123,
                access_token='', token='',
            )

    def test_regular_download_does_not_fetch_secure_boot_firmware(self):
        """Keep BIOS image selection without downloading a Secure Boot sidecar."""
        with mock.patch('sys.argv', ['getbuild.py', '--platform', 'vs', '--buildid', '123']), \
                mock.patch.object(getbuild, 'get_download_url', return_value=(ARTIFACT_URL, 10)), \
                mock.patch.object(getbuild, 'download_artifacts') as image, \
                mock.patch.object(getbuild, 'download_secure_boot_firmware') as firmware:
            getbuild.main()
            image.assert_called_once_with(
                ARTIFACT_URL, 'image', 'vs', 123, 1, access_token='', token='', secure_boot=False,
            )
            firmware.assert_not_called()

    def test_secure_boot_rejects_unsupported_downloads_before_network_access(self):
        """Reject non-VS, multi-ASIC, and archive requests rather than downloading BIOS."""
        for options in (
            ['--platform', 'ptf'],
            ['--platform', 'vs', '--num_asic', '4'],
            ['--platform', 'vs', '--content', 'all'],
        ):
            with self.subTest(options=options), \
                    mock.patch('sys.argv', ['getbuild.py', '--secure-boot'] + options), \
                    mock.patch.object(getbuild, 'get_download_url') as download_url, \
                    mock.patch.object(getbuild, 'find_latest_build_id') as latest, \
                    contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as error:
                getbuild.main()
            self.assertEqual(error.exception.code, 2)
            download_url.assert_not_called()
            latest.assert_not_called()

    def test_missing_firmware_fails_instead_of_accepting_a_stale_file(self):
        """Fail preparation when the selected build has no enrolled firmware."""
        opener = mock.Mock()
        opener.open.side_effect = getbuild.HTTPError(ARTIFACT_URL, 404, 'Not Found', {}, None)
        with mock.patch.object(getbuild, 'build_opener', return_value=opener), \
                mock.patch('builtins.open') as output, \
                self.assertRaisesRegex(RuntimeError, 'not present in build 123'):
            getbuild.download_secure_boot_firmware(
                ARTIFACT_URL, 'sonic-vs_vars.fd', 'sonic-vs_vars.fd', 123, '', '',
            )
        output.assert_not_called()


if __name__ == '__main__':
    unittest.main()
