"""Mutation controls for the narrow Glob clock and exact tool paths."""
import copy, json, unittest
from core_tool_acceptance import ROOT, sha
from search_tool_acceptance import MATRIX_SHA256, SearchNormalize


class SearchControls(unittest.TestCase):
    def test_complete_authored_matrix(self):
        matrix = ROOT / "search-tool-cases.json"
        self.assertEqual(sha(matrix), MATRIX_SHA256)
        rows = json.loads(matrix.read_bytes())
        self.assertEqual([r['id'].split('-')[0] for r in rows], [f'G{i:02}' for i in range(1, 14)])
        self.assertEqual(rows[9]['tools'][0]['input']['path'], '/work')
        self.assertEqual(rows[-1]['env'], {'RIPGREP_CONFIG_PATH': '/fixtures/ignored-rg.conf'})

    def test_only_exact_glob_result_clock_is_normalized(self):
        result = dict(filenames=['input.txt'], durationMs=7, numFiles=1, truncated=False, totalMatches=1, countIsComplete=True)
        normalizer = SearchNormalize('C:\\owned')
        changed = normalizer.value(result, '/protocol_frames/2/tool_use_result')
        self.assertEqual(changed['durationMs'], '$GLOB_ELAPSED')
        self.assertEqual(normalizer.audit, [{'path':'/protocol_frames/2/tool_use_result/durationMs','value':7,'kind':'glob_elapsed_time'}])
        self.assertEqual(normalizer.value(result, '/requests/2/body'), result)
        extra = dict(result, extra='semantic')
        self.assertEqual(normalizer.value(extra, '/protocol_frames/2/tool_use_result'), extra)
        for invalid in [-1, True, '7']:
            with self.subTest(invalid=invalid), self.assertRaises(AssertionError):
                normalizer.value(dict(result, durationMs=invalid), '/protocol_frames/2/tool_use_result')
        modified = copy.deepcopy(result); modified['numFiles'] = 2
        self.assertNotEqual(normalizer.value(modified, '/protocol_frames/2/tool_use_result'), changed)


if __name__ == '__main__': unittest.main()
