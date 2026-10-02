"""패키징/정책 점검: 의존성, Dockerfile, compose, 금지 구성요소 (CLAUDE.md 1, 3, 5, 6, 8장)."""
import ast
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNTIME = {"fastapi", "uvicorn", "jinja2", "cryptography"}
TRANSITIVE = {"annotated-doc", "annotated-types", "anyio", "cffi", "click", "h11", "idna", "markupsafe",
              "opentelemetry-api", "pycparser", "pydantic", "pydantic-core", "starlette", "typing-extensions",
              "typing-inspection"}
FORBIDDEN = {"httpx", "pytest", "pip-audit", "pip-tools", "python-multipart", "multipart", "uvloop", "httptools",
             "websockets", "watchfiles", "python-dotenv", "pyyaml", "itsdangerous", "orjson", "ujson", "email-validator",
             "bcrypt", "argon2-cffi", "passlib", "python-jose", "sqlalchemy", "alembic", "requests", "pandas", "aiofiles",
             "slowapi", "authlib", "fastapi-users"}


def requirement_blocks(text: str) -> list[tuple[str, str]]:
    blocks = re.split(r"\n(?=[A-Za-z0-9_.-]+==)", text)
    return [(m.group(1).lower(), block) for block in blocks if (m := re.match(r"([A-Za-z0-9_.-]+)==", block))]


class RequirementsTests(unittest.TestCase):
    def test_runtime_requirements_are_pinned_with_hashes_and_minimal(self):
        blocks = requirement_blocks((ROOT / "requirements.txt").read_text())
        names = {n for n, _ in blocks}
        self.assertTrue(RUNTIME <= names)
        self.assertEqual(names - RUNTIME - TRANSITIVE, set(), "허용 목록 밖의 패키지가 있다 (추가 전에 승인 필요)")
        self.assertEqual(names & FORBIDDEN, set())
        for name, block in blocks:
            self.assertRegex(block, r"==\d", name)
            self.assertIn("--hash=sha256:", block, f"{name}: 해시 누락")
        self.assertNotIn("[standard]", (ROOT / "requirements.txt").read_text())

    def test_input_files(self):
        self.assertEqual({l.strip() for l in (ROOT / "requirements.in").read_text().splitlines() if l.strip()}, RUNTIME)
        dev = (ROOT / "requirements-dev.in").read_text()
        for needed in ("-r requirements.in", "httpx", "pip-audit", "pip-tools"):
            self.assertIn(needed, dev)
        self.assertNotIn("standard", (ROOT / "requirements.in").read_text())

    def test_application_imports_only_stdlib_and_allowed_packages(self):
        allowed = set(sys.stdlib_module_names) | {"fastapi", "starlette", "pydantic", "jinja2", "cryptography", "uvicorn", "app"}
        bad = []
        for path in (ROOT / "app").rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                modules = []
                if isinstance(node, ast.Import):
                    modules = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    modules = [node.module.split(".")[0]]
                bad += [f"{path.relative_to(ROOT)}: {m}" for m in modules if m not in allowed]
        self.assertEqual(bad, [])


class DockerTests(unittest.TestCase):
    def setUp(self):
        self.dockerfile = (ROOT / "Dockerfile").read_text()
        self.compose = (ROOT / "docker-compose.yml").read_text()

    def test_multistage_build_with_hashes_and_no_pip_in_final_image(self):
        stages = re.findall(r"^FROM (\S+)(?: AS (\S+))?", self.dockerfile, re.M)
        self.assertEqual(len(stages), 2)
        self.assertTrue(all(image == "python:3.13-slim" for image, _ in stages))
        build, final = self.dockerfile.split("AS build", 1)[1].split("\nFROM python:3.13-slim\n")
        self.assertIn("python -m venv /opt/venv", build)
        self.assertIn("pip install --require-hashes -r", build)
        self.assertIn("pip uninstall -y pip setuptools", build)
        self.assertIn("COPY --from=build /opt/venv /opt/venv", final)
        self.assertIn("pip uninstall -y pip setuptools wheel", final)
        self.assertNotIn("pip install", final)
        for secret_like in ("COPY . ", "COPY tests", ".env", "secret.key"):
            self.assertNotIn(secret_like, final)

    def test_runtime_settings(self):
        for line in ("PYTHONDONTWRITEBYTECODE=1", "PYTHONUNBUFFERED=1", "USER 10001:10001", "--gid 10001", "--uid 10001"):
            self.assertIn(line, self.dockerfile)
        self.assertRegex(self.dockerfile, r'CMD \["python", "-m", "app", "serve"\]')
        self.assertRegex(self.dockerfile, r'HEALTHCHECK [^\n]*\\\n\s+CMD \["python", "-m", "app", "healthcheck"\]')
        self.assertIn("EXPOSE 8080", self.dockerfile)
        self.assertNotIn("--reload", self.dockerfile)
        self.assertNotIn("root", self.dockerfile.split("USER 10001:10001")[1])

    def test_compose_matches_the_specified_minimal_shape(self):
        expected = """
services:
  app:
    build: .
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      ADMIN_ENABLED: "true"
    volumes:
      - data:/data
    read_only: true
    tmpfs:
      - /tmp
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    mem_limit: 512m

volumes:
  data:
"""
        def significant(text):
            return [re.sub(r"\s+#.*$", "", line).rstrip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
        self.assertEqual(significant(self.compose), significant(expected))
        self.assertNotIn("0.0.0.0", self.compose)
        self.assertNotIn("env_file", self.compose)

    def test_dockerignore_keeps_secrets_and_tests_out(self):
        ignore = (ROOT / ".dockerignore").read_text().split()
        for entry in (".git", ".venv", "tests", "*.db"):
            self.assertIn(entry, ignore)


class PolicyTests(unittest.TestCase):
    def app_files(self, *suffixes):
        return [p for p in (ROOT / "app").rglob("*") if p.is_file() and p.suffix in suffixes and "__pycache__" not in p.parts]

    def test_no_sql_string_building(self):
        # CLAUDE.md 8장: grep -rnE "execute\(f|execute\(.*%|execute\(.*\+" app/ 결과가 0건
        pattern = re.compile(r"execute\(f|execute\(.*%|execute\(.*\+")
        hits = [f"{p.relative_to(ROOT)}:{n}" for p in self.app_files(".py") for n, line in enumerate(p.read_text().splitlines(), 1)
                if pattern.search(line)]
        self.assertEqual(hits, [])

    def test_template_safety(self):
        # grep -rnE "\|safe|Markup\(|autoescape false" app/ 결과가 0건
        pattern = re.compile(r"\|safe|Markup\(|autoescape false")
        hits = [str(p.relative_to(ROOT)) for p in self.app_files(".py", ".html") if pattern.search(p.read_text())]
        self.assertEqual(hits, [])

    def test_no_inline_script_style_or_handlers(self):
        pattern = re.compile(r"<script>|<style|style=|\son[a-z]+=\"", re.I)
        hits = [str(p.relative_to(ROOT)) for p in self.app_files(".html") if pattern.search(p.read_text())]
        self.assertEqual(hits, [])

    def test_no_external_resources(self):
        external = re.compile(r"""(?:src|href)=["']https?://|url\(\s*["']?https?://|@import|//cdn\.|googleapis|fonts\.""", re.I)
        hits = [str(p.relative_to(ROOT)) for p in self.app_files(".html", ".css", ".js") if external.search(p.read_text())]
        self.assertEqual(hits, [])

    def test_static_assets_are_minimal_and_no_frontend_toolchain(self):
        self.assertEqual({p.name for p in (ROOT / "app" / "static").iterdir()} - {"app.js"}, {"style.css"})
        for name in ("package.json", "package-lock.json", "yarn.lock", "node_modules", "webpack.config.js", "vite.config.js",
                     "tailwind.config.js", ".env"):
            self.assertFalse((ROOT / name).exists(), name)

    def test_project_layout(self):
        for rel in ("app/main.py", "app/__main__.py", "app/db.py", "app/security.py", "app/forms.py", "app/schemas.py",
                    "app/assets.py", "app/csvio.py", "app/audit.py", "app/migrations/001_init.sql", "app/templates/base.html",
                    "app/templates/macros.html", "app/static/style.css", "tests", "Dockerfile", "docker-compose.yml",
                    "requirements.txt", "requirements-dev.in"):
            self.assertTrue((ROOT / rel).exists(), rel)
        for router in ("auth", "dashboard", "servers", "services", "models", "licenses", "search", "tags", "users", "audit", "backup"):
            self.assertTrue((ROOT / "app" / "routers" / f"{router}.py").exists(), router)

    def test_only_one_environment_variable_is_read(self):
        reads = []
        for p in self.app_files(".py"):
            reads += re.findall(r"os\.environ(?:\.get)?\(?\[?[\"'](\w+)[\"']", p.read_text())
        self.assertEqual(set(reads), {"ADMIN_ENABLED"})


if __name__ == "__main__":
    unittest.main()
