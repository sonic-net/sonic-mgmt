import logging
import time
from pkg_resources import parse_version


class SysfsNotExistError(Exception):
    """
    Exception when sys fs not exist.
    """
    pass


class MockerBaseHelper:
    """
    Mellanox specified mocker helper.
    """
    unlink_file_list = {}
    regular_file_list = {}

    def __init__(self, dut):
        """
        Constructor of mocker helper.
        :param dut: DUT object representing a SONiC switch under test.
        """
        self.dut = dut
        self.deinit_retry = 5

    def mock_value(self, file_path, value, force=False):
        """
        Unlink existing sys fs file and replace it with a new one. Write given value to the new file.
        :param file_path: Sys fs file path.
        :param value: Value to write to sys fs file.
        :param force: Force mock even if the file does not exist.
        :return:
        """
        if file_path not in self.regular_file_list and file_path not in self.unlink_file_list:
            out = self.dut.stat(path=file_path)
            exist = True
            if not out['stat']['exists']:
                if force:
                    exist = False
                else:
                    raise SysfsNotExistError('{} not exist'.format(file_path))
            if exist and out['stat']['islnk']:
                self._unlink(file_path)
            else:
                self._cache_file_value(file_path, force)
        self.dut.shell('echo \'{}\' > {}'.format(value, file_path))

    def read_value(self, file_path):
        """
        Read sys fs file content.
        :param file_path: Sys fs file path.
        :return: Content of sys fs file.
        """
        out = self.dut.stat(path=file_path)
        if not out['stat']['exists']:
            raise SysfsNotExistError('{} not exist'.format(file_path))
        try:
            output = self.dut.command("cat %s" % file_path)
            value = output["stdout"]
            return value.strip()
        except Exception as e:
            assert 0, "Get content from %s failed, exception: %s" % (
                file_path, repr(e))

    def _cache_file_value(self, file_path, may_nexist=False):
        """
        Cache file value for regular file.
        :param file_path: Regular file path.
        :return:
        """
        try:
            output = self.dut.command("cat %s" % file_path)
            value = output["stdout"]
            self.regular_file_list[file_path] = value.strip()
        except Exception as e:
            if may_nexist:
                self.regular_file_list[file_path] = None
            else:
                assert 0, "Get content from %s failed, exception: %s" % (
                    file_path, repr(e))

    def _unlink(self, file_path):
        """
        Unlink given sys fs file, record its soft link target.
        :param file_path: Sys fs file path.
        :return:
        """
        readlink_output = self.dut.command('readlink {}'.format(file_path))
        self.unlink_file_list[file_path] = readlink_output["stdout"]
        self.dut.command('unlink {}'.format(file_path))
        self.dut.command('touch {}'.format(file_path))
        self.dut.command('chown admin {}'.format(file_path))

    def deinit(self):
        """
        Destructor of MockerHelper. Re-link all sys fs files.
        :return:
        """
        failed_recover_links = {}
        for file_path, link_target in list(self.unlink_file_list.items()):
            try:
                self.dut.command(
                    'ln -f -s {} {}'.format(link_target, file_path))
            except Exception:
                # Catch any exception for later retry
                failed_recover_links[file_path] = link_target

        failed_recover_files = {}
        for file_path, value in list(self.regular_file_list.items()):
            try:
                if value is None:
                    self.dut.shell('rm -f {}'.format(file_path))
                else:
                    self.dut.shell('echo \'{}\' > {}'.format(value, file_path))
            except Exception:
                # Catch any exception for later retry
                failed_recover_files[file_path] = value

        self.unlink_file_list.clear()
        self.regular_file_list.clear()
        # If there is any failed recover files, retry it
        if failed_recover_links or failed_recover_files:
            self.deinit_retry -= 1
            if self.deinit_retry > 0:
                self.unlink_file_list = failed_recover_links
                self.regular_file_list = failed_recover_files
                # The failed files might be used by other sonic daemons, delay 1 second
                # here to avoid conflict
                time.sleep(1)
                self.deinit()
            else:
                # We don't want to retry it infinite, and 5 times retry
                # is enough, so if it still fails after the retry, it
                # means there is probably an issue with our sysfs, we need
                # mark it fail here
                failed_recover_files.update(failed_recover_links)
                error_message = "Failed to recover all files, failed files: {}".format(
                    failed_recover_files)
                logging.error(error_message)
                raise RuntimeError(error_message)

    def is_201911(self):
        """
        Workaround to make thermal control test cases compatible with 201911 and master
        :return:
        """
        if parse_version(self.dut.kernel_version) > parse_version('4.9.0'):
            return False
        else:
            return True