import json
from pathlib import Path

ROOT = Path(__file__).parents[2]
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
WARM_CACHES = (ROOT / ".github" / "workflows" / "warm-ci-caches.yml").read_text(encoding="utf-8")
PYTHON_CI = (ROOT / "scripts" / "run-python-ci.sh").read_text(encoding="utf-8")
STABLE = (ROOT / ".github" / "workflows" / "release-stable.yml").read_text(encoding="utf-8")
PREPARE_STABLE = (ROOT / ".github" / "workflows" / "prepare-stable-tag.yml").read_text(
    encoding="utf-8"
)
IMAGES = (ROOT / ".github" / "workflows" / "release-images.yml").read_text(encoding="utf-8")
PYPI = (ROOT / ".github" / "workflows" / "publish-pypi.yml").read_text(encoding="utf-8")
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")


def _image_workflow_step(name: str) -> str:
    marker = f"      - name: {name}"
    start = IMAGES.index(marker)
    end = IMAGES.find("\n      - ", start + len(marker))
    return IMAGES[start:] if end == -1 else IMAGES[start:end]


def test_stable_release_is_a_fail_closed_draft_handoff() -> None:
    source_job = STABLE.split("  build-source-dist:", 1)[1].split("\n  test:", 1)[0]
    assert "validate-release-source:" in STABLE
    assert "python scripts/release_contract.py validate-source" in STABLE
    assert "+refs/heads/main:refs/remotes/origin/main" in STABLE
    assert "$GITHUB_REPOSITORY/.github/workflows/release-stable.yml@refs/tags/$TAG" in STABLE
    assert "Run the stable workflow from the exact release tag ref" in STABLE
    assert "python scripts/release_contract.py collect-stable" in STABLE
    assert "python scripts/release_contract.py validate-sdist" in STABLE
    assert '--archive "dist/marty_credentials-${TAG#v}.tar.gz"' in STABLE
    assert '"/Cargo.toml"' in PYPROJECT
    assert '"/Cargo.lock"' in PYPROJECT
    assert "dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4" in source_job
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


def test_stable_tag_requires_exact_main_gate_evidence() -> None:
    policy = (ROOT / ".github" / "stable-tag-policy.json").read_text(encoding="utf-8")
    for path in (
        ".github/workflows/ci.yml",
        ".github/workflows/open-source-policy.yml",
        ".github/workflows/organization-quality.yml",
        ".github/workflows/license-compliance.yml",
        "dynamic/github-code-scanning/codeql",
    ):
        assert path in policy
    assert "scripts/stable_tag_gate.py prepare" in PREPARE_STABLE
    assert "git ls-remote --tags" in PREPARE_STABLE
    assert "git tag -a" in PREPARE_STABLE
    assert "stable-tag-evidence-${{ inputs.tag }}" in PREPARE_STABLE
    assert "gh workflow run release-stable.yml --ref" in PREPARE_STABLE
    assert "scripts/stable_tag_gate.py validate-release" in STABLE
    assert "gh run download" in STABLE
    assert "actions: read" in STABLE


def test_stable_tag_push_gates_run_on_main() -> None:
    policy = json.loads((ROOT / ".github" / "stable-tag-policy.json").read_text(encoding="utf-8"))
    for requirement in policy["required_workflows"]:
        path = requirement["path"]
        if requirement["event"] != "push" or not path.startswith(".github/workflows/"):
            continue
        workflow = (ROOT / path).read_text(encoding="utf-8")
        assert "on:\n  push:\n    branches: [main]" in workflow, path


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
    assert "validate-spdx-package-denylist" in IMAGES
    assert "release/retired-python-packages.txt" in IMAGES
    assert "--method PATCH" in IMAGES
    assert "-F draft=false" in IMAGES
    assert "softprops/action-gh-release" not in IMAGES
    assert "sha256sum ./* > SHA256SUMS" not in IMAGES
    assert "43d14bc2b83dec42d39ecae14e916627a18bb661" not in IMAGES
    assert (
        IMAGES.count("actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8")
        == 2
    )


def test_release_image_sbom_is_checked_before_evidence_upload() -> None:
    matrix_job = IMAGES.split("  publish-by-digest:", 1)[1].split("\n  finalize-release:", 1)[0]
    sbom_position = matrix_job.index("anchore/sbom-action@")
    denylist_position = matrix_job.index("validate-spdx-package-denylist")
    upload_position = matrix_job.index("actions/upload-artifact@")

    assert sbom_position < denylist_position < upload_position


def test_historical_verification_smoke_gate_precedes_attestation() -> None:
    matrix_job = IMAGES.split("  publish-by-digest:", 1)[1].split("\n  finalize-release:", 1)[0]
    build_position = matrix_job.index("- id: build")
    smoke_position = matrix_job.index("Prove the historical verification image migrates and starts")
    attest_position = matrix_job.index("- uses: actions/attest-build-provenance@")

    assert build_position < smoke_position < attest_position
    assert "if: matrix.service == 'verification'" in matrix_job
    assert "python scripts/smoke_verification_image.py" in matrix_job
    assert "marty-credentials-verification@${{ steps.build.outputs.digest }}" in matrix_job
    assert (
        "postgres@sha256:3d0f7584ed7d04e27fa050d6683a74746608faf21f202be78460d679cc56461f"
        in matrix_job
    )


def test_release_tool_installs_are_version_pinned() -> None:
    assert "curl https://rustwasm.github.io/wasm-pack" not in STABLE
    assert "cargo install wasm-pack --version 0.15.0 --locked" in STABLE
    assert "cargo install cargo-cyclonedx --version 0.5.9 --locked" in STABLE
    assert "cargo install git-cliff --version 2.13.1 --locked" in STABLE
    assert "python -m pip install build==1.5.0" in STABLE
    assert (
        "python scripts/install_pinned_core.py --repository . --destination release-deps" in STABLE
    )
    assert "python -m pip install pytest==9.1.1" in STABLE
    assert "hatchling==1.31.0" not in PYPROJECT
    assert "hatchling==1.32.0" in PYPROJECT
    assert "hatch-vcs==0.5.0" in PYPROJECT
    assert "maturin==1.14.1" in PYPROJECT


def test_stable_release_excludes_unsupported_linux_arm64_wheel() -> None:
    wheel_matrix = STABLE.split("  build-python-wheels:", 1)[1].split("\n  build-wasm:", 1)[0]
    assert "- os: ubuntu-latest\n            target: aarch64" in wheel_matrix


def test_ci_installs_exact_source_built_core_artifacts_with_released_features() -> None:
    assert CI.count("run: bash scripts/run-python-ci.sh") == 2
    assert "release-deps" in PYTHON_CI
    assert "len(wheels) == 2" in PYTHON_CI
    assert "install_pinned_core.py" not in PYTHON_CI
    assert "ref: ${{ env.MARTY_CORE_REVISION }}" in CI
    assert "marty-core/marty-bindings/Cargo.toml" in CI
    assert "marty-core/marty-verification/Cargo.toml" in CI
    released_verification_features = "--features pyo3/extension-module,python,csca,eudi"
    assert released_verification_features in CI
    assert released_verification_features in WARM_CACHES
    assert "cert-builder" not in CI
    assert "cert-builder" not in WARM_CACHES
    assert "authority-issuance" not in CI
    assert "authority-issuance" not in WARM_CACHES


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
    assert "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c" not in IMAGES
    assert IMAGES.count("docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e") == 2
    assert IMAGES.count("docker/login-action@dbcb813823bdd20940b903addbd779551569679f") == 2


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


def test_image_release_derives_one_canonical_handoff_from_the_checked_out_tag() -> None:
    validate = IMAGES.split("  validate-draft:", 1)[1].split("\n  publish-by-digest:", 1)[0]
    matrix_job = IMAGES.split("  publish-by-digest:", 1)[1].split("\n  finalize-release:", 1)[0]

    assert "ref: ${{ github.sha }}" in validate
    assert "ref: ${{ steps.contract.outputs.tag }}" in validate
    assert "path: release-source" in validate
    assert "Tag must be a canonical stable release tag" in validate
    binding_position = validate.index("Validate the tag binding before running tag-scoped code")
    handoff_position = validate.index("Derive the canonical tag-scoped service matrix")
    tag_code_position = validate.index("release-source/scripts/release_contract.py validate-source")
    assert binding_position < handoff_position < tag_code_position
    assert 'rev-parse "refs/tags/$TAG^{commit}"' in validate
    assert "merge-base --is-ancestor" in validate
    assert "scripts/release_service_handoff.py" in validate
    assert "--repository release-source" in validate
    assert "service_matrix: ${{ steps.service_contract.outputs.service_matrix }}" in validate
    assert "release-source/scripts/release_contract.py validate-source" in validate
    assert "release-source/scripts/release_contract.py validate-release" in validate
    assert "matrix: ${{ fromJSON(needs.validate-draft.outputs.service_matrix) }}" in matrix_job
    assert IMAGES.count("ref: ${{ needs.validate-draft.outputs.commit }}") == 2


def test_every_service_specific_release_phase_consumes_the_same_handoff() -> None:
    release_state = _image_workflow_step("Validate source and draft by numeric release ID")
    terminal = IMAGES.split('if [ "$STATE" = terminal ]; then', 1)[1].split(
        'elif [ "$STATE" = complete ]', 1
    )[0]
    matrix_job = IMAGES.split("  publish-by-digest:", 1)[1].split("\n  finalize-release:", 1)[0]
    steps = [
        _image_workflow_step("Revalidate and download draft assets by release ID"),
        _image_workflow_step("Create and verify one final checksum manifest"),
        _image_workflow_step("Upload only missing evidence to the exact draft"),
        _image_workflow_step("Promote every verified service digest to the stable tag"),
        _image_workflow_step("Publish the exact complete draft once"),
    ]

    assert "SERVICE_MATRIX: ${{ steps.service_contract.outputs.service_matrix }}" in release_state
    assert ".include[].service" in release_state
    assert 'done <<< "$service_lines"' in terminal
    assert "matrix: ${{ fromJSON(needs.validate-draft.outputs.service_matrix) }}" in matrix_job
    assert matrix_job.count("${{ matrix.service }}") >= 8
    for step in steps:
        assert "SERVICE_MATRIX: ${{ needs.validate-draft.outputs.service_matrix }}" in step
        assert ".include[].service" in step
    assert "< <(jq -er '.include[].service'" not in IMAGES
    assert "for service in issuance" not in IMAGES
    assert "service: issuance" not in matrix_job


def test_partial_and_complete_draft_recovery_cover_every_handoff_service() -> None:
    matrix_job = IMAGES.split("  publish-by-digest:", 1)[1].split("\n  finalize-release:", 1)[0]
    reconcile = _image_workflow_step("Revalidate and download draft assets by release ID")
    promote = _image_workflow_step("Promote every verified service digest to the stable tag")
    prepublish = _image_workflow_step("Publish the exact complete draft once")

    assert "if: needs.validate-draft.outputs.state == 'build'" in matrix_job
    assert "matrix: ${{ fromJSON(needs.validate-draft.outputs.service_matrix) }}" in matrix_job
    assert "for suffix in digest spdx.json; do" in reconcile
    assert "Existing $name differs from the rebuilt evidence" in reconcile
    assert "needs.validate-draft.outputs.state == 'complete'" in IMAGES
    assert "needs.publish-by-digest.result == 'skipped'" in IMAGES
    assert "--phase complete-draft" in _image_workflow_step(
        "Validate complete draft before image tag promotion"
    )
    assert "docker buildx imagetools create" in promote
    assert "package-after-$service.json" in promote
    assert "package-prepublish-$service.json" in prepublish


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
    assert "Promote the verified issuance digest" not in matrix_job
    assert "docker buildx imagetools create" not in matrix_job
    assert "--method PATCH" not in matrix_job


def test_current_contract_does_not_statically_republish_retired_verification_image() -> None:
    matrix_job = IMAGES.split("  publish-by-digest:", 1)[1].split("\n  finalize-release:", 1)[0]
    assert "matrix: ${{ fromJSON(needs.validate-draft.outputs.service_matrix) }}" in matrix_job
    assert "service: issuance" not in matrix_job
    assert "service: verification" not in matrix_job
    assert "if: matrix.service == 'verification'" in matrix_job
    assert "verification-session-postgres" not in CI


def test_finalization_order_prevents_partial_release_publication() -> None:
    build_position = IMAGES.index("- id: build")
    finalize_position = IMAGES.index("  finalize-release:")
    finalize = IMAGES[finalize_position:]
    complete_position = finalize.index("Validate complete draft before image tag promotion")
    prepromotion_check_position = finalize.index(
        "Revalidate the remote tag before image tag promotion"
    )
    prepromotion_tag_ref_position = finalize.index("git/ref/tags/$TAG", prepromotion_check_position)
    promote_position = finalize.index("Promote every verified service digest to the stable tag")
    promotion_command_position = finalize.index("docker buildx imagetools create")
    publish_position = finalize.index("Publish the exact complete draft once")
    prepublish_tag_ref_position = finalize.index("git/ref/tags/$TAG", publish_position)
    asset_digest_position = finalize.index(
        "Remote release digest for $name changed before publication"
    )
    package_recheck_position = finalize.index("package-prepublish-$service.json")
    patch_position = finalize.index("--method PATCH")

    assert build_position < finalize_position
    assert (
        complete_position
        < prepromotion_check_position
        < prepromotion_tag_ref_position
        < promote_position
        < promotion_command_position
    )
    assert (
        promotion_command_position
        < publish_position
        < asset_digest_position
        < prepublish_tag_ref_position
        < package_recheck_position
        < patch_position
    )
    assert finalize.count("git/ref/tags/$TAG") == 2
    assert finalize.count("docker buildx imagetools create") == 1
    assert finalize.count("--method PATCH") == 1
    assert "validate-package-tag-absent" not in finalize
    assert "--allow-absent" in finalize
    assert "release-prepublish.json" in finalize
