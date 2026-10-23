#!/usr/bin/env python3
"""
Unit tests for setup.sh, tutorial.md, and Cloud Shell button integration.
"""

import os
import re
import stat
import subprocess
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SETUP_SCRIPT = os.path.join(REPO_ROOT, "setup.sh")
TUTORIAL_FILE = os.path.join(REPO_ROOT, "tutorial.md")
README_FILE = os.path.join(REPO_ROOT, "README.md")
CONSUMER_MAIN_TF = os.path.join(REPO_ROOT, "infra", "consumer", "main.tf")
CONSUMER_VARS_TF = os.path.join(REPO_ROOT, "infra", "consumer", "variables.tf")


class TestSetupScript(unittest.TestCase):
    """Verifies setup.sh script integrity, flags, validation, and documentation."""

    def test_setup_script_exists_and_is_executable(self):
        self.assertTrue(os.path.isfile(SETUP_SCRIPT), "setup.sh must exist at repo root")
        mode = os.stat(SETUP_SCRIPT).st_mode
        self.assertTrue(bool(mode & stat.S_IXUSR), "setup.sh must be executable by user")

    def test_setup_script_syntax(self):
        res = subprocess.run(["bash", "-n", SETUP_SCRIPT], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"bash -n setup.sh failed with error:\n{res.stderr}")

    def test_setup_script_help_flag(self):
        res = subprocess.run([SETUP_SCRIPT, "--help"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("CodeMender Slim - Cloud Run & Wiz Setup", res.stdout)
        self.assertIn("--project", res.stdout)
        self.assertIn("--region", res.stdout)
        self.assertIn("--job-name", res.stdout)
        self.assertIn("--dry-run", res.stdout)

    def test_setup_script_dry_run_validation(self):
        # When non-interactive and credentials are missing, it should fail validation cleanly
        env = dict(os.environ, PATH=os.environ.get("PATH", ""))
        env.pop("WIZ_CLIENT_ID", None)
        env.pop("WIZ_CLIENT_SECRET", None)
        env["IMAGE_URI"] = "example.com/img:tag"

        res = subprocess.run(
            [SETUP_SCRIPT, "--dry-run", "-y", "-p", "test-project", "-r", "us-central1"],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("WIZ_CLIENT_ID must be provided", res.stderr + res.stdout)

    def test_setup_script_dry_run_success(self):
        env = dict(
            os.environ,
            WIZ_CLIENT_ID="mock-client-id",
            WIZ_CLIENT_SECRET="mock-client-secret",
            WIZ_DATACENTER="us20",
            IMAGE_URI="example.com/img:tag",
        )
        env.pop("CONFIGURE_WIF", None)
        env.pop("GITHUB_REPO", None)
        res = subprocess.run(
            [
                SETUP_SCRIPT,
                "--dry-run",
                "-y",
                "-p",
                "test-project",
                "-r",
                "us-central1",
                "-j",
                "wiz-codemender-slim",
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(res.returncode, 0, f"setup.sh --dry-run failed:\n{res.stderr}")
        out = res.stdout
        self.assertIn("Active Project: test-project", out)
        self.assertIn("Deployment Region: us-central1", out)
        self.assertIn(
            "Checking required APIs: run.googleapis.com secretmanager.googleapis.com "
            "aiplatform.googleapis.com logging.googleapis.com iam.googleapis.com storage.googleapis.com",
            out,
        )
        self.assertIn("Simulating secret creation for 'wiz-mcp-config'", out)
        self.assertIn("codemender-slim-runner@test-project.iam.gserviceaccount.com", out)
        self.assertIn("gs://test-project-codemender-artifacts", out)
        self.assertIn("roles/storage.objectUser", out)
        self.assertIn("SCAN_ARTIFACTS_BUCKET=test-project-codemender-artifacts", out)
        self.assertIn("Cloud Run Job 'wiz-codemender-slim' configured", out)
        self.assertIn("[7/7]", out)
        self.assertIn("Configuration Completed", out)
        self.assertIn("GCP_PROJECT=test-project", out)
        self.assertIn("uses: <OWNER>/<REPO>/.github/workflows/codemender.yml@main", out)
        self.assertNotIn("rapture-lighthouse", out)
        self.assertNotIn("wif-provider:", out)

    def test_setup_script_dry_run_with_wif(self):
        env = dict(
            os.environ,
            WIZ_CLIENT_ID="mock-client-id",
            WIZ_CLIENT_SECRET="mock-client-secret",
            WIZ_DATACENTER="us20",
            IMAGE_URI="example.com/img:tag",
        )
        res = subprocess.run(
            [
                SETUP_SCRIPT,
                "--dry-run",
                "-y",
                "-p",
                "test-project",
                "--wif",
                "--github-repo",
                "wiz-demo/codemender-gemini-action",
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(res.returncode, 0, f"setup.sh with WIF failed:\n{res.stderr}")
        out = res.stdout
        self.assertIn("Simulating WIF setup for repository: wiz-demo/codemender-gemini-action", out)
        self.assertIn("WIF Provider:", out)
        self.assertIn("workloadIdentityPools/codemender-pool/providers/github-provider", out)
        self.assertIn("WIF_SERVICE_ACCOUNT=codemender-slim-runner@test-project.iam.gserviceaccount.com", out)
        self.assertIn("wif-provider: ${{ vars.WIF_PROVIDER }}", out)
        self.assertIn("wif-service-account: ${{ vars.WIF_SERVICE_ACCOUNT }}", out)

    def _cloud_shell_env(self, **extra):
        env = dict(
            os.environ,
            WIZ_CLIENT_ID="mock-client-id",
            WIZ_CLIENT_SECRET="mock-client-secret",
            WIZ_DATACENTER="us20",
            CONFIGURE_WIF="false",
            CLOUD_SHELL="true",
            IMAGE_URI="example.com/img:tag",
        )
        for key in ("PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "DEVSHELL_PROJECT_ID"):
            env.pop(key, None)
        env.update(extra)
        return env

    def test_setup_script_detects_cloud_shell_project(self):
        # Interactive mode (no -y) with stdin closed: must not prompt for the project.
        res = subprocess.run(
            [SETUP_SCRIPT, "--dry-run", "-r", "us-central1"],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            env=self._cloud_shell_env(GOOGLE_CLOUD_PROJECT="cs-session-proj"),
        )
        self.assertEqual(res.returncode, 0, f"Cloud Shell detection failed:\n{res.stdout}\n{res.stderr}")
        self.assertIn("Detected Cloud Shell project cs-session-proj (via GOOGLE_CLOUD_PROJECT)", res.stdout)
        self.assertIn("Active Project: cs-session-proj", res.stdout)
        self.assertNotIn("Enter Google Cloud Project ID", res.stdout)

    def test_setup_script_detects_devshell_project_fallback(self):
        env = self._cloud_shell_env(DEVSHELL_PROJECT_ID="devshell-proj")
        env.pop("CLOUD_SHELL")
        res = subprocess.run(
            [SETUP_SCRIPT, "--dry-run", "-r", "us-central1"],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            env=env,
        )
        self.assertEqual(res.returncode, 0, f"DEVSHELL fallback failed:\n{res.stdout}\n{res.stderr}")
        self.assertIn("Active Project: devshell-proj", res.stdout)

    def test_setup_script_explicit_project_overrides_cloud_shell(self):
        res = subprocess.run(
            [SETUP_SCRIPT, "--dry-run", "-r", "us-central1", "-p", "explicit-proj"],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            env=self._cloud_shell_env(GOOGLE_CLOUD_PROJECT="cs-session-proj"),
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("Active Project: explicit-proj", res.stdout)
        self.assertNotIn("Detected Cloud Shell project", res.stdout)

    def test_readme_contains_cloud_shell_button(self):
        self.assertTrue(os.path.isfile(README_FILE), "README.md must exist")
        with open(README_FILE, "r", encoding="utf-8") as f:
            content = f.read()

        # Cloud Shell button image badge
        self.assertIn("https://gstatic.com/cloudssh/images/open-btn.svg", content)
        # Cloud Shell open URL
        self.assertIn("https://shell.cloud.google.com/cloudshell/open", content)
        self.assertIn("cloudshell_git_repo=", content)
        self.assertIn("cloudshell_tutorial=tutorial.md", content)
        # Setup documentation
        self.assertIn("./setup.sh", content)
        self.assertIn("< 3 minutes", content)
        self.assertIn("codemender-artifacts", content)

    def test_tutorial_walkthrough_file(self):
        self.assertTrue(os.path.isfile(TUTORIAL_FILE), "tutorial.md must exist")
        with open(TUTORIAL_FILE, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("<walkthrough-tutorial-duration duration=\"3\"></walkthrough-tutorial-duration>", content)
        self.assertIn("./setup.sh", content)
        self.assertIn("run.googleapis.com", content)
        self.assertIn("secretmanager.googleapis.com", content)
        self.assertIn("storage.googleapis.com", content)
        self.assertIn("<walkthrough-project-setup></walkthrough-project-setup>", content)
        self.assertIn("gcloud config set project <walkthrough-project-id/>", content)
        self.assertIn("codemender-artifacts", content)
        self.assertIn("wiz-mcp-config", content)
        self.assertIn("wiz-codemender-slim", content)


class TestSetupScriptTerraformParity(unittest.TestCase):
    """Keeps setup.sh in sync with infra/consumer Terraform (the source of truth)."""

    @classmethod
    def setUpClass(cls):
        with open(SETUP_SCRIPT, "r", encoding="utf-8") as f:
            cls.script = f.read()
        with open(CONSUMER_MAIN_TF, "r", encoding="utf-8") as f:
            cls.main_tf = f.read()
        with open(CONSUMER_VARS_TF, "r", encoding="utf-8") as f:
            cls.vars_tf = f.read()

    def _tf_default(self, var_name):
        m = re.search(
            r'variable\s+"%s"\s*\{[^}]*?default\s*=\s*"([^"]*)"' % re.escape(var_name),
            self.vars_tf,
            re.S,
        )
        self.assertIsNotNone(m, f"variable {var_name} default not found in variables.tf")
        return m.group(1)

    def test_required_apis_match(self):
        api_block = re.search(r'google_project_service"\s+"enabled_apis".*?toset\(\[(.*?)\]\)', self.main_tf, re.S)
        self.assertIsNotNone(api_block)
        tf_apis = set(re.findall(r'"([a-z]+\.googleapis\.com)"', api_block.group(1)))
        sh_block = re.search(r"REQUIRED_APIS=\((.*?)\)", self.script, re.S)
        sh_apis = set(re.findall(r'"([a-z]+\.googleapis\.com)"', sh_block.group(1)))
        self.assertEqual(tf_apis, sh_apis)

    def test_project_iam_roles_match(self):
        tf_roles = set(
            re.findall(
                r'resource\s+"google_project_iam_member".*?role\s*=\s*"(roles/[^"]+)"',
                self.main_tf,
                re.S,
            )
        )
        sh_block = re.search(r"REQUIRED_ROLES=\((.*?)\)", self.script, re.S)
        sh_roles = set(re.findall(r'"(roles/[^"]+)"', sh_block.group(1)))
        self.assertEqual(tf_roles, sh_roles)

    def test_bucket_and_job_env_match(self):
        self.assertIn('"${var.project_id}-codemender-artifacts"', self.main_tf)
        self.assertIn('ARTIFACTS_BUCKET="${PROJECT_ID}-codemender-artifacts"', self.script)
        self.assertIn("roles/storage.objectUser", self.main_tf)
        self.assertIn("roles/storage.objectUser", self.script)
        tf_env = set(re.findall(r'env\s*\{\s*name\s*=\s*"([A-Z_]+)"', self.main_tf))
        env_line = re.search(r'^ENV_VARS="([^"]+)"', self.script, re.M)
        self.assertIsNotNone(env_line)
        sh_env = {kv.split("=", 1)[0] for kv in env_line.group(1).split(",")}
        self.assertEqual(tf_env, sh_env)

    def test_defaults_match(self):
        for tf_var, sh_var in [
            ("job_name", "JOB_NAME"),
            ("runner_sa_name", "RUNNER_SA_NAME"),
            ("wiz_secret_name", "WIZ_SECRET_NAME"),
            ("wif_pool_name", "WIF_POOL_NAME"),
            ("wif_provider_name", "WIF_PROVIDER_NAME"),
        ]:
            expected = self._tf_default(tf_var)
            self.assertIn(f'{sh_var}="${{{sh_var}:-{expected}}}"', self.script, f"{sh_var} default drifted from {tf_var}")

        retries = re.search(r"max_retries\s*=\s*(\d+)", self.main_tf).group(1)
        self.assertIn(f'JOB_MAX_RETRIES="${{JOB_MAX_RETRIES:-{retries}}}"', self.script)


HOST_MAIN_TF = os.path.join(REPO_ROOT, "infra", "host", "main.tf")
HOST_VARS_TF = os.path.join(REPO_ROOT, "infra", "host", "variables.tf")


def _run(args, **env_extra):
    env = dict(os.environ, WIZ_CLIENT_ID="mock-id", WIZ_CLIENT_SECRET="mock-secret", WIZ_DATACENTER="app")
    for key in ("CONFIGURE_WIF", "GITHUB_REPO", "IMAGE_URI", "PROVISION_BUILDER", "BUILDER_ONLY", "COLLAPSED"):
        env.pop(key, None)
    # Consumer-only runs need an explicit image (no default); builder modes derive it.
    if not {"--builder", "--collapsed"} & set(args):
        env["IMAGE_URI"] = "example.com/img:tag"
    env.update(env_extra)
    return subprocess.run(
        [SETUP_SCRIPT, "--dry-run", "-y"] + args,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env=env,
    )


class TestSetupScriptBuilderModes(unittest.TestCase):
    """--builder (host only) and --collapsed (host + consumer, shared WIF)."""

    def test_builder_only_provisions_host_resources_and_skips_consumer(self):
        res = _run(["-p", "host-proj", "--builder", "--github-owner", "wiz-demo", "--pull-member", "serviceAccount:svc@x.iam.gserviceaccount.com"])
        self.assertEqual(res.returncode, 0, res.stderr)
        out = res.stdout
        self.assertIn("[3/3] Configuring builder resources", out)
        self.assertIn("codemender-slim-builder@host-proj.iam.gserviceaccount.com", out)
        self.assertIn("attribute.repository_owner/wiz-demo", out)
        self.assertIn("roles/artifactregistry.reader on 'wiz-codemender-images' for serviceAccount:svc@x.iam.gserviceaccount.com", out)
        self.assertIn("WIF_SERVICE_ACCOUNT=codemender-slim-builder@host-proj.iam.gserviceaccount.com", out)
        self.assertIn("AR_REPO=wiz-codemender-images", out)
        # Consumer steps must not run.
        self.assertNotIn("Configuring Cloud Run Job", out)
        self.assertNotIn("Wiz Security Graph MCP credentials", out)

    def test_collapsed_shares_wif_with_distinct_service_accounts(self):
        res = _run(["-p", "one-proj", "--collapsed", "--github-owner", "acme", "--github-repo", "acme/app"])
        self.assertEqual(res.returncode, 0, res.stderr)
        out = res.stdout
        self.assertIn("[8/8] Configuring Cloud Run Job", out)
        builder = "codemender-slim-builder@one-proj.iam.gserviceaccount.com"
        runner = "codemender-slim-runner@one-proj.iam.gserviceaccount.com"
        self.assertIn(f"WIF_SERVICE_ACCOUNT={builder}", out)
        self.assertIn(f"WIF_SERVICE_ACCOUNT={runner}", out)
        # One WIF pool/provider, created/checked once, used by both identities.
        self.assertEqual(out.count("Simulating WIF pool 'codemender-pool'"), 1)
        self.assertIn("Collapsed mode: runner shares WIF pool 'codemender-pool'", out)
        providers = set(re.findall(r"projects/\d+/locations/global/workloadIdentityPools/[^/\s]+/providers/[^\s]+", out))
        self.assertEqual(len(providers), 1, providers)
        # Consumer job points at the image this project's builder publishes.
        self.assertIn("Image: us-central1-docker.pkg.dev/one-proj/wiz-codemender-images/worker:slim", out)

    def test_collapsed_respects_explicit_image(self):
        res = _run(["-p", "one-proj", "--collapsed", "--github-owner", "acme", "--github-repo", "acme/app", "--image", "example.com/img:tag"])
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("Image: example.com/img:tag", res.stdout)

    def test_collapsed_rejects_same_service_account(self):
        res = _run(["-p", "p", "--collapsed", "-s", "same", "--builder-sa-name", "same"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("requires distinct service accounts", res.stderr)

    def test_builder_requires_explicit_github_owner(self):
        for mode in ("--builder", "--collapsed"):
            res = _run(["-p", "p", mode, "--github-repo", "acme/app"])
            self.assertNotEqual(res.returncode, 0, mode)
            self.assertIn("--github-owner <OWNER> (or GITHUB_OWNER) is required", res.stderr)
            self.assertNotIn("rapture-lighthouse", res.stdout + res.stderr)

    def test_no_hardcoded_owner_defaults(self):
        with open(SETUP_SCRIPT, "r", encoding="utf-8") as f:
            script = f.read()
        self.assertIn('GITHUB_OWNER="${GITHUB_OWNER:-}"', script)
        self.assertIn('CALLER_WORKFLOW_REF="${CALLER_WORKFLOW_REF:-}"', script)
        self.assertIn('IMAGE_URI="${IMAGE_URI:-}"', script)
        self.assertNotIn("urithuru", script)
        self.assertNotIn("rapture-lighthouse", script)

    def test_consumer_requires_explicit_image(self):
        res = _run(["-p", "p"], IMAGE_URI="")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("--image <IMAGE_URI> (or IMAGE_URI) is required", res.stderr)

    def test_caller_workflow_ref_flag(self):
        res = _run(["-p", "p", "--caller-workflow-ref", "wiz-demo/codemender-gemini-action/.github/workflows/codemender.yml@v1"])
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("uses: wiz-demo/codemender-gemini-action/.github/workflows/codemender.yml@v1", res.stdout)

    def test_builder_and_collapsed_are_mutually_exclusive(self):
        res = _run(["-p", "p", "--builder", "--collapsed"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("mutually exclusive", res.stderr)

    def test_wif_provider_includes_attribute_condition(self):
        with open(SETUP_SCRIPT, "r", encoding="utf-8") as f:
            script = f.read()
        self.assertIn("--attribute-condition=", script)
        self.assertIn("assertion.repository_owner ==", script)

    def test_secret_payload_keys(self):
        with open(SETUP_SCRIPT, "r", encoding="utf-8") as f:
            script = f.read()
        self.assertIn("'datacenter': sys.argv[3]", script)
        self.assertIn("'mcp_url': sys.argv[4]", script)
        self.assertNotIn("WIZ_ENV", script)
        self.assertNotIn("--wiz-env", script)

    def test_datacenter_required_non_interactive(self):
        res = _run(["-p", "p"], WIZ_DATACENTER="")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("A valid Wiz DataCenter", res.stderr)

    def test_datacenter_rejects_invalid_value(self):
        res = _run(["-p", "p", "--datacenter", "us 20!"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Invalid Wiz DataCenter", res.stderr)

    def test_datacenter_required_interactive_blank_input(self):
        # Blank entry re-prompts; EOF afterwards exits instead of looping forever.
        env = dict(os.environ, WIZ_CLIENT_ID="mock-id", WIZ_CLIENT_SECRET="mock-secret", WIZ_DATACENTER="",
                   IMAGE_URI="example.com/img:tag", CONFIGURE_WIF="false")
        res = subprocess.run([SETUP_SCRIPT, "--dry-run", "-p", "p", "-r", "us-central1"],
                             input="\n", capture_output=True, text=True, env=env)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Wiz DataCenter is required and cannot be blank", res.stderr)
        self.assertIn("No input received; the Wiz DataCenter is required", res.stderr)

    def test_tenant_env_defaults_to_app(self):
        res = _run(["-p", "p", "--datacenter", "US20"])
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("Wiz DataCenter: us20", res.stdout)
        self.assertIn("https://mcp.app.wiz.io?mode=explicit", res.stdout)

    def test_tenant_env_selects_mcp_url(self):
        res = _run(["-p", "p", "--datacenter", "us20", "--tenant-env", "Demo"])
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("https://mcp.demo.wiz.io?mode=explicit", res.stdout)

    def test_tenant_env_prompt_interactive(self):
        env = dict(os.environ, WIZ_CLIENT_ID="mock-id", WIZ_CLIENT_SECRET="mock-secret", WIZ_DATACENTER="us20",
                   IMAGE_URI="example.com/img:tag", CONFIGURE_WIF="false")
        res = subprocess.run([SETUP_SCRIPT, "--dry-run", "-p", "p", "-r", "us-central1"],
                             input="demo\n", capture_output=True, text=True, env=env)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("https://mcp.demo.wiz.io?mode=explicit", res.stdout)

    def test_tenant_env_rejects_invalid_value(self):
        res = _run(["-p", "p", "--datacenter", "us20", "--tenant-env", "evil.com/x"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Invalid Wiz Tenant Env", res.stderr)

    def test_wiz_env_flag_removed(self):
        res = _run(["-p", "p", "--datacenter", "us20", "--wiz-env", "demo"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Unknown option: --wiz-env", res.stderr)


class TestSetupScriptHostTerraformParity(unittest.TestCase):
    """Keeps the builder path in sync with infra/host Terraform."""

    @classmethod
    def setUpClass(cls):
        with open(SETUP_SCRIPT, "r", encoding="utf-8") as f:
            cls.script = f.read()
        with open(HOST_MAIN_TF, "r", encoding="utf-8") as f:
            cls.main_tf = f.read()
        with open(HOST_VARS_TF, "r", encoding="utf-8") as f:
            cls.vars_tf = f.read()

    def _tf_default(self, var_name):
        m = re.search(r'variable\s+"%s"\s*\{[^}]*?default\s*=\s*"([^"]*)"' % re.escape(var_name), self.vars_tf, re.S)
        self.assertIsNotNone(m, f"variable {var_name} default not found in infra/host/variables.tf")
        return m.group(1)

    def test_builder_apis_match(self):
        tf_block = re.search(r'google_project_service"\s+"enabled_apis".*?toset\(\[(.*?)\]\)', self.main_tf, re.S)
        tf_apis = set(re.findall(r'"([a-z]+\.googleapis\.com)"', tf_block.group(1)))
        sh_block = re.search(r"BUILDER_APIS=\((.*?)\)", self.script, re.S)
        sh_apis = set(re.findall(r'"([a-z]+\.googleapis\.com)"', sh_block.group(1)))
        self.assertEqual(tf_apis, sh_apis)

    def test_builder_roles_match(self):
        tf_roles = set(re.findall(r'resource\s+"google_project_iam_member".*?role\s*=\s*"(roles/[^"]+)"', self.main_tf, re.S))
        sh_block = re.search(r"BUILDER_ROLES=\((.*?)\)", self.script, re.S)
        sh_roles = set(re.findall(r'"(roles/[^"]+)"', sh_block.group(1)))
        self.assertEqual(tf_roles, sh_roles)

    def test_builder_wif_binding_scope_matches(self):
        self.assertIn("attribute.repository_owner/${var.github_owner}", self.main_tf)
        self.assertIn("attribute.repository_owner/${GITHUB_OWNER}", self.script)

    def test_builder_defaults_match(self):
        for tf_var, sh_var in [
            ("builder_sa_name", "BUILDER_SA_NAME"),
            ("artifact_registry_repo", "AR_REPO"),
            ("wif_pool_name", "WIF_POOL_NAME"),
            ("wif_provider_name", "WIF_PROVIDER_NAME"),
        ]:
            expected = self._tf_default(tf_var)
            self.assertIn(f'{sh_var}="${{{sh_var}:-{expected}}}"', self.script, f"{sh_var} default drifted from {tf_var}")


if __name__ == "__main__":
    unittest.main()
