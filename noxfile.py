import nox


source_files = ("irl/", "noxfile.py", "tests/")


@nox.session(reuse_venv=True)
def lint(session):
    session.install("black", "autoflake")
    session.run("autoflake", "--recursive", *source_files)
    session.run("black", "--target-version=py36", *source_files)

    check(session)


@nox.session(reuse_venv=True)
def check(session):
    session.install("black", "flake8")
    session.run("black", "--check", "--target-version=py36", *source_files)
    session.run("flake8", "--max-line-length=88", "--ignore=E203", *source_files)


@nox.session(python=["3.6", "3.7", "3.8"])
def test(session):
    session.install("pytest", "pytest-cov")
    session.install(".")
    session.run(
        "coverage",
        "run",
        "--omit='*'",
        "-m",
        "pytest",
        "--cov=irl",
        "--cov-report=term-missing",
        *session.posargs,
    )
