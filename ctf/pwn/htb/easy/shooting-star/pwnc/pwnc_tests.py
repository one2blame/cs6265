import unittest
import pwnc

class TestMain(unittest.TestCase):
    
    def test_valid_symbols(self):
        symbols = {"strncpy": "0xdb0", "strcat": "0xd800"}
        self.assertEqual(pwnc._query_build_id(symbols), 
                                "libc6_2.27-3ubuntu1.2_amd64")

    def test_valid_buildid(self):
        symbols = ["system", "strcat"]
        buildid = "libc6_2.27-3ubuntu1.2_amd64"
        results = pwnc._query_symbols(symbols, buildid)
        self.assertEqual(results['strcat'], "0x9d800")
        self.assertEqual(results['system'], "0x4f4e0")

    def test_valid_query(self):
        symbols = {"strncpy": "0xdb0", "strcat": "0xd800"}
        desired_symbols = ["system", "strcat"]
        results = pwnc.query(desired_symbols, symbols)
        self.assertEqual(results['strcat'], "0x9d800")
        self.assertEqual(results['system'], "0x4f4e0")

    def test_valid_libc_download(self):
        symbols = {"strncpy": "0xdb0", "strcat": "0xd800"}
        libc = pwnc.get_libc(symbols)
        self.assertIn(b"__libc_start_main", libc)

if __name__ == "__main__":
    unittest.main()
