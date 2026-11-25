"""Check the source and r6 build contract before dispatching to Xcode."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import projections


class ProjectionWorkflowTests(unittest.TestCase):
    def test_both_jobs_require_the_resolved_revision(self):
        p = projections.CONFIG
        for stage in (p["build"], p["check"]):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as tmp, \
                    mock.patch.dict(os.environ, {p["revision_env"]: p["source_branch"]}), \
                    mock.patch.object(projections.subprocess, "check_output", return_value=p["target"]), \
                    mock.patch.object(projections.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    projections.run(stage, Path(tmp), Path(tmp))
                run.assert_not_called()

    def test_real_build_recipe_pins_r6_and_cleans_failed_exports(self):
        p = projections.CONFIG
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {p["revision_env"]: p["source_branch"]}), \
                mock.patch.object(projections.subprocess, "check_output", return_value=p["source_branch"]), \
                mock.patch.object(projections.subprocess, "run", side_effect=[
                    None, None, None, subprocess.CalledProcessError(1, p["verifier"])]) as runs:
            work = Path(tmp)
            with self.assertRaises(subprocess.CalledProcessError):
                projections.run(p["build"], work, work)
            arguments = [call.args[0] for call in runs.call_args_list]
            self.assertTrue(any(p["package"] in value for value in arguments[1]))
            self.assertTrue(any(p["package_sha256"] in value for value in arguments[1]))
            self.assertIn(p["target"], arguments[2])
            self.assertIn(p["verifier"], arguments[3])
            self.assertFalse((work / p["build_dir"]).exists())
