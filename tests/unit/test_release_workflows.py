from pathlib import Path

ROOT = Path(__file__).parents[2]
STABLE = (ROOT / ".github" / "workflows" / "release-stable.yml").read_text(encoding="utf-8")
IMAGES = (ROOT / ".github" / "workflows" / "release-images.yml").read_text(encoding="utf-8")
PYPI = (ROOT / ".github" / "workflows" / "publish-pypi.yml").read_text(encoding="utf-8")
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_stable_release_is_a_fail_closed_draft_handoff() -> None:
    assert "validate-release-source:" in STABLE
    assert "python scripts/release_contract.py validate-source" in STABLE
    assert "+refs/heads/main:refs/remotes/origin/main" in STABLE
    assert "$GITHUB_REPOSITORY/.github/workflows/release-stable.yml@refs/tags/$TAG" in STABLE
    assert "Run the stable workflow from the exact release tag ref" in STABLE
    assert "python scripts/release_contract.py collect-stable" in STABLE
    # Repository immutability is enabled out of band because GITHUB_TOKEN has
    # no Administration permission for the immutable-releases endpoint.
    assert "immutable-releases" not in STABLE
    assert "gh release create" in STABLE
    assert "--draft" in STABLE
    assert "--verify-tag" in STABLE
    assert "--clobber" not in STABLE
    assert "credentials-release-draft-ready" in STABLE
    assert "client_payload[release_id]" in STABLE
    assert "client_payload[commit_sha]" in STABLE
    assert "softprops/action-gh-release" not in STABLE
    assert "SHA256SUMS" not in STABLE


def test_image_release_uses_exact_draft_and_digest_first_publication() -> None:
    assert "types: [credentials-release-draft-ready]" in IMAGES
    assert "release_id:" in IMAGES
    assert "commit_sha:" in IMAGES
    assert "validate-draft:" in IMAGES
    assert "python scripts/release_contract.py validate-release" in IMAGES
    assert "immutable-releases" not in IMAGES
    assert "--phase resumable" in IMAGES
    assert "--phase published" in IMAGES
    assert "+refs/heads/main:refs/remotes/origin/main" in IMAGES
    assert "push-by-digest=true" in IMAGES
    assert "name-canonical=true" in IMAGES
    assert "python scripts/release_contract.py write-checksums" in IMAGES
    assert "python scripts/release_contract.py verify-checksums" in IMAGES
    assert "python scripts/release_contract.py list-stable-assets" in IMAGES
    assert "gh attestation verify" in IMAGES
    assert "--signer-workflow" in IMAGES
    assert "$GITHUB_REPOSITORY/.github/workflows/release-stable.yml" in IMAGES
    assert '--source-ref "refs/tags/$TAG"' in IMAGES
    assert '--source-digest "$COMMIT"' in IMAGES
    assert "--deny-self-hosted-runners" in IMAGES
    assert "SHA256SUMS.sigstore.json" in IMAGES
    assert "uploads.github.com" in IMAGES
    assert ".digest == $digest" in IMAGES
    assert "cmp --silent" in IMAGES
    assert "docker buildx imagetools create" in IMAGES
    assert "--method PATCH" in IMAGES
    assert "-F draft=false" in IMAGES
    assert "softprops/action-gh-release" not in IMAGES
    assert "sha256sum ./* > SHA256SUMS" not in IMAGES
    assert "43d14bc2b83dec42d39ecae14e916627a18bb661" not in IMAGES
    assert (
        IMAGES.count("actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a")
        == 2
    )


def test_release_tool_installs_are_version_pinned() -> None:
    assert "curl https://rustwasm.github.io/wasm-pack" not in STABLE
    assert "cargo install wasm-pack --version 0.15.0 --locked" in STABLE
    assert "cargo install cargo-cyclonedx --version 0.5.9 --locked" in STABLE
    assert "cargo install git-cliff --version 2.13.1 --locked" in STABLE
    assert "python -m pip install build==1.5.0" in STABLE
    assert "python -m pip install maturin==1.14.1 pytest==9.1.1" in STABLE
    assert "hatchling==1.31.0" in PYPROJECT
    assert "hatch-vcs==0.5.0" in PYPROJECT
    assert "maturin==1.14.1" in PYPROJECT


def test_pypi_waits_for_the_immutable_stable_release() -> None:
    assert "workflow_call:" in PYPI
    assert "workflow_dispatch:" in PYPI
    assert "push:" not in PYPI
    assert "python scripts/release_contract.py validate-source" in PYPI
    assert "--phase published" in PYPI
    assert "gh attestation verify" in PYPI
    assert "marty_credentials-$VERSION.tar.gz" in PYPI
    assert "python -m build" not in PYPI
    assert "uses: ./.github/workflows/publish-pypi.yml" in IMAGES
    assert "needs.finalize-release.result == 'success'" in IMAGES


def test_deprecated_mutable_release_workflows_are_removed() -> None:
    workflows = ROOT / ".github" / "workflows"
    assert not (workflows / "release-rc.yml").exists()
    assert not (workflows / "cleanup-artifacts.yml").exists()
    assert "v0.2.0-rc.1" not in README
    assert "rustwasm.github.io/wasm-pack/installer" not in README


def test_docker_actions_use_verified_node24_commits() -> None:
    assert "8d2750c68a42422c14e847fe6c8ac0403b4cbd6f" not in IMAGES
    assert "c94ce9fb468520275223c153574b00df6fe4bcc9" not in IMAGES
    assert IMAGES.count("docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c") == 2
    assert IMAGES.count("docker/login-action@af1e73f918a031802d376d3c8bbc3fe56130a9b0") == 2


def test_image_release_has_fail_closed_recovery_states() -> None:
    assert "state: ${{ steps.release_state.outputs.state }}" in IMAGES
    assert 'echo "state=$STATE" >> "$GITHUB_OUTPUT"' in IMAGES
    assert "if: needs.validate-draft.outputs.state == 'build'" in IMAGES
    assert "needs.validate-draft.outputs.state == 'complete'" in IMAGES
    assert "needs.publish-by-digest.result == 'skipped'" in IMAGES
    assert "if: needs.validate-draft.outputs.state != 'complete'" in IMAGES
    assert "Verify the existing complete-payload attestation" in IMAGES
    assert "for artifact in release-assets/*" in IMAGES
    assert "cp existing-assets/SHA256SUMS.sigstore.json" in IMAGES
    assert "cosign verify-blob" in IMAGES
    assert "Existing $name is identical; retaining it" in IMAGES


def test_terminal_recovery_verifies_release_assets_and_image_tags() -> None:
    terminal = IMAGES.split('if [ "$STATE" = terminal ]; then', 1)[1].split(
        'elif [ "$STATE" = complete ]', 1
    )[0]
    assert "marty-credentials-$service.digest" in terminal
    assert "API digest does not match its bytes" in terminal
    assert "package-terminal-$service.json" in terminal
    assert "validate-package-tag" in terminal
    assert "--allow-absent" not in terminal


def test_versioned_image_tags_are_not_written_by_matrix_builds() -> None:
    matrix_job = IMAGES.split("  publish-by-digest:", 1)[1].split("\n  finalize-release:", 1)[0]
    assert matrix_job.index("- id: build") < matrix_job.index("- uses: actions/attest")
    assert "tags:" not in matrix_job
    assert "push: true" not in matrix_job
    assert "outputs: type=image" in matrix_job
    assert "Promote both verified digests" not in matrix_job
    assert "docker buildx imagetools create" not in matrix_job
    assert "--method PATCH" not in matrix_job


def test_finalization_order_prevents_partial_release_publication() -> None:
    build_position = IMAGES.index("- id: build")
    finalize_position = IMAGES.index("  finalize-release:")
    finalize = IMAGES[finalize_position:]
    complete_position = finalize.index("Validate complete draft before image tag promotion")
    promote_position = finalize.index("Promote both verified digests to the stable tag")
    promotion_command_position = finalize.index("docker buildx imagetools create")
    publish_position = finalize.index("Publish the exact complete draft once")
    tag_ref_position = finalize.index("git/ref/tags/$TAG")
    asset_digest_position = finalize.index(
        "Remote release digest for $name changed before publication"
    )
    package_recheck_position = finalize.index("package-prepublish-$service.json")
    patch_position = finalize.index("--method PATCH")

    assert build_position < finalize_position
    assert complete_position < promote_position < promotion_command_position
    assert (
        promotion_command_position
        < publish_position
        < asset_digest_position
        < tag_ref_position
        < package_recheck_position
        < patch_position
    )
    assert finalize.count("docker buildx imagetools create") == 1
    assert finalize.count("--method PATCH") == 1
    assert "validate-package-tag-absent" not in finalize
    assert "--allow-absent" in finalize
    assert "release-prepublish.json" in finalize
