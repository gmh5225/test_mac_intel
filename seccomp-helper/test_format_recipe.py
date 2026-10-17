import hashlib
import unittest
from format_recipe import formatted


class FormatBoundaryTests(unittest.TestCase):
    def recipe(self, result, operations):
        return {"original_bytes": 3, "readable_bytes": len(result), "readable_sha256": hashlib.sha256(result).hexdigest(), "insertions": operations}

    def test_only_exact_whitespace_projection(self):
        self.assertEqual(formatted(b"x{}", self.recipe(b"x{\n  }\n", [[2, "\n  "], [3, "\n"]])), b"x{\n  }\n")
        for operations in [[[2, "code"]], [[4, "\n"]], [[2, "\n"], [1, " "]], [[2, " "]], [[2, ""]]]:
            with self.assertRaises(AssertionError): formatted(b"x{}", self.recipe(b"x{\n  }\n", operations))


if __name__ == "__main__": unittest.main()
