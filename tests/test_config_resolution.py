#!/usr/bin/env python3
"""
Unit tests for CodeMender configuration and command policy resolution.

Tests the precedence behavior:
1. Sub-repository .codemender directory files take precedence when present.
2. Worker image's burnt-in .codemender folder serves as fallback.
3. Partial overrides (only config.yaml or only command_policy.yaml) fall back individually.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ENTRYPOINT_PATH = os.path.join(REPO_ROOT, "worker", "entrypoint.sh")
WORKER_CODEMENDER = os.path.join(REPO_ROOT, "worker", ".codemender")


class TestConfigResolution(unittest.TestCase):
    """Verifies that sub-repo .codemender overrides worker fallback appropriately."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.home_dir = os.path.join(self.test_dir, "home")
        self.repo_dir = os.path.join(self.test_dir, "repo")
        self.worker_fallback_dir = os.path.join(self.test_dir, "worker_codemender")

        os.makedirs(self.home_dir, exist_ok=True)
        os.makedirs(self.repo_dir, exist_ok=True)
        # Pre-populate HOME/.codemender to simulate the image's baked-in /root/.codemender
        shutil.copytree(WORKER_CODEMENDER, os.path.join(self.home_dir, ".codemender"))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _run_setup_codemender_config(self, extra_env=None):
        """Runs the setup_codemender_config function extracted from entrypoint.sh in bash."""
        env = dict(os.environ)
        env["HOME"] = self.home_dir
        env["WORKSPACE_DIR"] = self.test_dir
        env["REPO_DIR"] = self.repo_dir
        env["ARTIFACTS_DIR"] = os.path.join(self.test_dir, "artifacts")
        env["REPO"] = "wiz-demo/talisman"
        env["PROJECT_ID"] = "test-project"

        if extra_env:
            env.update(extra_env)

        bash_cmd = f"""
        set -euo pipefail
        # Load functions from entrypoint.sh without executing main entrypoint logic
        source <(sed '/^setup_auth_and_workspace$/d; /^"run_${{ACTION}}"$/d' "{ENTRYPOINT_PATH}")
        setup_codemender_config
        """
        result = subprocess.run(
            ["bash", "-c", bash_cmd],
            env=env,
            capture_output=True,
            text=True,
        )
        return result

    def test_both_config_and_policy_from_subrepo(self):
        """When sub-repo provides both config and command_policy, both should be used."""
        subrepo_cm = os.path.join(self.repo_dir, ".codemender")
        os.makedirs(subrepo_cm, exist_ok=True)
        custom_config = "model: 'custom-subrepo-model'\nbuild:\n  command: 'subrepo build'\n"
        custom_policy = "allowed_commands:\n  - 'subrepo-tool'\n"

        with open(os.path.join(subrepo_cm, "config.yaml"), "w") as f:
            f.write(custom_config)
        with open(os.path.join(subrepo_cm, "command_policy.yaml"), "w") as f:
            f.write(custom_policy)

        res = self._run_setup_codemender_config()
        self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}\n{res.stdout}")

        active_config_path = os.path.join(self.home_dir, ".codemender", "config.yaml")
        active_policy_path = os.path.join(self.home_dir, ".codemender", "command_policy.yaml")

        self.assertTrue(os.path.isfile(active_config_path))
        self.assertTrue(os.path.isfile(active_policy_path))

        with open(active_config_path) as f:
            self.assertEqual(f.read(), custom_config)
        with open(active_policy_path) as f:
            self.assertEqual(f.read(), custom_policy)

        self.assertIn("Using repository CodeMender configuration", res.stdout)
        self.assertIn("Using repository CodeMender command policy", res.stdout)

    def test_fallback_when_subrepo_has_no_codemender(self):
        """When sub-repo has no .codemender directory, worker fallback should be used."""
        res = self._run_setup_codemender_config()
        self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}\n{res.stdout}")

        active_config_path = os.path.join(self.home_dir, ".codemender", "config.yaml")
        active_policy_path = os.path.join(self.home_dir, ".codemender", "command_policy.yaml")

        self.assertTrue(os.path.isfile(active_config_path))
        self.assertTrue(os.path.isfile(active_policy_path))

        with open(os.path.join(WORKER_CODEMENDER, "config.yaml")) as f:
            expected_config = f.read()
        with open(os.path.join(WORKER_CODEMENDER, "command_policy.yaml")) as f:
            expected_policy = f.read()

        with open(active_config_path) as f:
            self.assertEqual(f.read(), expected_config)
        with open(active_policy_path) as f:
            self.assertEqual(f.read(), expected_policy)

        self.assertIn("No .codemender in repository; continuing with baked-in", res.stdout)

    def test_partial_override_config_only(self):
        """When sub-repo provides only config.yaml, command_policy.yaml remains baked-in."""
        subrepo_cm = os.path.join(self.repo_dir, ".codemender")
        os.makedirs(subrepo_cm, exist_ok=True)
        custom_config = "model: 'subrepo-only-model'\n"
        with open(os.path.join(subrepo_cm, "config.yaml"), "w") as f:
            f.write(custom_config)

        res = self._run_setup_codemender_config()
        self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}\n{res.stdout}")

        active_config_path = os.path.join(self.home_dir, ".codemender", "config.yaml")
        active_policy_path = os.path.join(self.home_dir, ".codemender", "command_policy.yaml")

        with open(active_config_path) as f:
            self.assertEqual(f.read(), custom_config)
        with open(os.path.join(WORKER_CODEMENDER, "command_policy.yaml")) as f:
            expected_policy = f.read()
        with open(active_policy_path) as f:
            self.assertEqual(f.read(), expected_policy)

        self.assertIn("Using repository CodeMender configuration", res.stdout)

    def test_partial_override_policy_only(self):
        """When sub-repo provides only command_policy.yaml, config.yaml remains baked-in."""
        subrepo_cm = os.path.join(self.repo_dir, ".codemender")
        os.makedirs(subrepo_cm, exist_ok=True)
        custom_policy = "allowed_commands:\n  - 'custom-tool'\n"
        with open(os.path.join(subrepo_cm, "command_policy.yaml"), "w") as f:
            f.write(custom_policy)

        res = self._run_setup_codemender_config()
        self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}\n{res.stdout}")

        active_config_path = os.path.join(self.home_dir, ".codemender", "config.yaml")
        active_policy_path = os.path.join(self.home_dir, ".codemender", "command_policy.yaml")

        with open(os.path.join(WORKER_CODEMENDER, "config.yaml")) as f:
            expected_config = f.read()
        with open(active_config_path) as f:
            self.assertEqual(f.read(), expected_config)
        with open(active_policy_path) as f:
            self.assertEqual(f.read(), custom_policy)

        self.assertIn("Using repository CodeMender command policy", res.stdout)

    def test_auxiliary_assets_sync(self):
        """When sub-repo provides additional assets in .codemender, they are copied to active dir."""
        subrepo_cm = os.path.join(self.repo_dir, ".codemender")
        os.makedirs(subrepo_cm, exist_ok=True)
        with open(os.path.join(subrepo_cm, "prompt_template.txt"), "w") as f:
            f.write("Custom Prompt Template")

        res = self._run_setup_codemender_config()
        self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}\n{res.stdout}")

        active_extra_path = os.path.join(self.home_dir, ".codemender", "prompt_template.txt")
        self.assertTrue(os.path.isfile(active_extra_path))
        with open(active_extra_path) as f:
            self.assertEqual(f.read(), "Custom Prompt Template")
        self.assertIn("Found .codemender in repository; applying overrides", res.stdout)

    def _run_bootstrap(self, action="remediate", target_files=(), extra_path=None):
        """Runs run_repo_bootstrap from entrypoint.sh and prints BASE_TOOLCHAIN_INVENTORY."""
        env = dict(os.environ)
        env["HOME"] = self.home_dir
        env["WORKSPACE_DIR"] = self.test_dir
        env["REPO_DIR"] = self.repo_dir
        env["ARTIFACTS_DIR"] = os.path.join(self.test_dir, "artifacts")
        env["REPO"] = "wiz-demo/meridian"
        env["PROJECT_ID"] = "test-project"
        env["CM_ACTION"] = action
        env["CM_BOOTSTRAP_TOOLS_FILE"] = os.path.join(self.test_dir, "bootstrap_tools.txt")
        if extra_path:
            env["PATH"] = f"{extra_path}:{env.get('PATH', '')}"

        args_str = " ".join(f'"{f}"' for f in target_files)
        bash_cmd = f"""
        set -euo pipefail
        source <(sed '/^setup_auth_and_workspace$/d; /^"run_${{ACTION}}"$/d' "{ENTRYPOINT_PATH}")
        setup_codemender_config
        run_repo_bootstrap {args_str}
        echo "INVENTORY_START"
        echo "${{BASE_TOOLCHAIN_INVENTORY}}"
        """
        return subprocess.run(
            ["bash", "-c", bash_cmd],
            env=env,
            capture_output=True,
            text=True,
        )

    def test_bootstrap_skipped_on_scan(self):
        """bootstrap.sh should never run during scan action."""
        subrepo_cm = os.path.join(self.repo_dir, ".codemender")
        os.makedirs(subrepo_cm, exist_ok=True)
        marker = os.path.join(self.test_dir, "ran_marker")
        with open(os.path.join(subrepo_cm, "bootstrap.sh"), "w") as f:
            f.write(f"#!/usr/bin/env bash\ntouch '{marker}'\n")

        res = self._run_bootstrap(action="scan", target_files=("src/app.rb",))
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse(os.path.exists(marker))

    def test_bootstrap_runs_on_verify_and_updates_inventory(self):
        """bootstrap.sh dynamically populates inventory from command_policy.yaml and CM_BOOTSTRAP_TOOLS_FILE."""
        subrepo_cm = os.path.join(self.repo_dir, ".codemender")
        fake_bin = os.path.join(self.test_dir, "fake_bin")
        os.makedirs(subrepo_cm, exist_ok=True)
        os.makedirs(fake_bin, exist_ok=True)
        args_file = os.path.join(self.test_dir, "bootstrap_args.txt")

        with open(os.path.join(subrepo_cm, "command_policy.yaml"), "w") as f:
            f.write("allowed_commands:\n  - 'git'\n  - 'lein'\n  - 'uninstalled-custom-compiler'\n")

        with open(os.path.join(subrepo_cm, "bootstrap.sh"), "w") as f:
            f.write(
                "#!/usr/bin/env bash\n"
                f"printf '%s\\n' \"${{CM_ACTION}}\" \"$@\" > '{args_file}'\n"
                f"printf '#!/bin/sh\\nexit 0\\n' > '{fake_bin}/lein'\n"
                f"printf '#!/bin/sh\\nexit 0\\n' > '{fake_bin}/dynamic-extra-tool'\n"
                f"chmod +x '{fake_bin}/lein' '{fake_bin}/dynamic-extra-tool'\n"
                "echo 'dynamic-extra-tool' >> \"${CM_BOOTSTRAP_TOOLS_FILE}\"\n"
            )

        res = self._run_bootstrap(
            action="verify",
            target_files=("services/reports/core.clj",),
            extra_path=fake_bin,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        with open(args_file) as f:
            self.assertEqual(f.read().splitlines(), ["verify", "services/reports/core.clj"])

        inventory = res.stdout.split("INVENTORY_START\n", 1)[1]
        pre_line = [l for l in inventory.splitlines() if l.startswith("- Pre-installed Tools:")][0]
        not_line = [l for l in inventory.splitlines() if l.startswith("- NOT Pre-installed:")][0]
        self.assertIn("lein", pre_line)
        self.assertIn("dynamic-extra-tool", pre_line)
        self.assertNotIn("lein", not_line)
        self.assertIn("uninstalled-custom-compiler", not_line)

    def test_bootstrap_failure_falls_back_gracefully(self):
        """Non-zero exit in bootstrap.sh logs a warning and does not abort the worker."""
        subrepo_cm = os.path.join(self.repo_dir, ".codemender")
        os.makedirs(subrepo_cm, exist_ok=True)
        with open(os.path.join(subrepo_cm, "bootstrap.sh"), "w") as f:
            f.write("#!/usr/bin/env bash\nexit 42\n")

        res = self._run_bootstrap(action="remediate", target_files=("services/backoffice/app.rb",))
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn(".codemender/bootstrap.sh failed; continuing with available worker toolchains", res.stdout)


if __name__ == "__main__":
    unittest.main()
