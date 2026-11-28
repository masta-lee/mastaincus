#!/usr/bin/env bash
# Only public release material enters the newly created guest.
set -euo pipefail
umask 077
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted &&
   ${GITHUB_REPOSITORY:-} == masta-lee/mastaincus && ${GITHUB_REF:-} == refs/heads/main ]]
[[ ${CANDIDATE_RUN:-} =~ ^[1-9][0-9]{0,18}$ && ${CANDIDATE_COMMIT:-} =~ ^[0-9a-f]{40}$ ]]
lab="${RUNNER_TEMP:?}/controller-runtime-lab"
version="v1.8.14-test.${CANDIDATE_COMMIT:0:7}"
package="incudal-$version-linux-amd64.tar.gz"
case "${1:-}" in
  fetch)
    mkdir -m 700 -- "$lab"
    cd -- "$lab"
    repo="repos/$GITHUB_REPOSITORY"
    gh api "$repo/actions/runs/$CANDIDATE_RUN" > run.json
    jq -e --arg head "$CANDIDATE_COMMIT" --arg repo "$GITHUB_REPOSITORY" '
      .head_sha == $head and .repository.full_name == $repo and
      .head_repository.full_name == $repo and .path == ".github/workflows/release.yml" and
      .event == "workflow_dispatch" and .status == "completed" and .conclusion == "success"
    ' run.json > /dev/null
    gh api "$repo/actions/runs/$CANDIDATE_RUN/artifacts?per_page=100" > artifacts.json
    jq -ce --arg n "${package%.tar.gz}" --arg head "$CANDIDATE_COMMIT" --argjson run "$CANDIDATE_RUN" '
      [.artifacts[] | select(.name == $n and .expired == false and
        .workflow_run.id == $run and .workflow_run.head_sha == $head)] |
      select(length == 1) | .[0] | select(.size_in_bytes > 0 and .size_in_bytes <= 300000000 and
        (.digest | test("^sha256:[0-9a-f]{64}$"))) | {id,size_in_bytes,digest}
    ' artifacts.json > artifact.json
    gh api "$repo/actions/artifacts/$(jq -r .id artifact.json)/zip" > package.zip
    [[ $(stat -c %s package.zip) == "$(jq -r .size_in_bytes artifact.json)" ]]
    [[ "sha256:$(sha256sum package.zip | cut -d' ' -f1)" == "$(jq -r .digest artifact.json)" ]]
    python3 - "$package" <<'PY'
import shutil, stat, sys, zipfile
from pathlib import Path

name = sys.argv[1]
with zipfile.ZipFile("package.zip") as archive:
    assert sorted(archive.namelist()) == [name, name + ".sig"]
    for item in archive.infolist():
        assert not item.flag_bits & 1 and not stat.S_ISLNK(item.external_attr >> 16)
        limit = 300000000 if item.filename == name else 128
        assert 0 < item.file_size <= limit
        with archive.open(item) as src, Path(item.filename).open("xb") as dst:
            shutil.copyfileobj(src, dst)
PY
    node --input-type=module - "$GITHUB_WORKSPACE" "$package" "$version" <<'JS'
import {pathToFileURL} from 'node:url'
import {createHash} from 'node:crypto'
import {createReadStream, readFileSync} from 'node:fs'
const [repo, file, version] = process.argv.slice(2)
const {verifyPanelDigest} = await import(pathToFileURL(repo + '/scripts/panel-package-signature.mjs'))
const digest = createHash('sha256')
for await (const chunk of createReadStream(file)) digest.update(chunk)
const sha = digest.digest('hex')
if (!verifyPanelDigest(version, 'amd64', sha, readFileSync(file + '.sig','utf8').trim())) throw Error('Panel signature rejected')
console.log('Verified signed AMD64 tar SHA256', sha)
JS
    ;;
  run)
    [[ -z ${GH_TOKEN:-} && -z ${GITHUB_TOKEN:-} && -s "$lab/$package" && -r /dev/kvm && -w /dev/kvm ]]
    python3 scripts/controller-runtime-lab.py host "$lab" "$CANDIDATE_COMMIT" "$package"
    ;;
  *) exit 2 ;;
esac
