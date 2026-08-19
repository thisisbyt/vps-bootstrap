import unittest

from app.system_info import parse_meminfo, parse_os_release


class SystemInfoTests(unittest.TestCase):
    def test_parse_os_release(self) -> None:
        data = parse_os_release('ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04 LTS"\n')

        self.assertEqual(data["ID"], "ubuntu")
        self.assertEqual(data["VERSION_ID"], "24.04")

    def test_parse_meminfo(self) -> None:
        memory = parse_meminfo("MemTotal:        2048000 kB\nSwapTotal:       1048576 kB\n")

        self.assertEqual(memory.ram_total_mb, 2000)
        self.assertEqual(memory.swap_total_mb, 1024)
