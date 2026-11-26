import { readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const docsSiteDir = resolve(fileURLToPath(new URL('..', import.meta.url)))
const repoRoot = resolve(docsSiteDir, '..')

function read(relativePath) {
  return readFileSync(resolve(repoRoot, relativePath), 'utf8')
}

function requireText(content, expected, label) {
  if (!content.includes(expected)) {
    throw new Error(`${label}: missing ${JSON.stringify(expected)}`)
  }
}

function rejectText(content, rejected, label) {
  if (content.includes(rejected)) {
    throw new Error(`${label}: contains forbidden ${JSON.stringify(rejected)}`)
  }
}

const installer = read('scripts/install-panel.sh')
for (const expected of [
  'is_atomic_layout()',
  'verify_release_checksum()',
  'validate_release_archive()',
  '检测到原子 OTA 布局'
]) {
  requireText(installer, expected, 'installer')
}

for (const path of [
  'docs-site/docs/deployment/manual-install.md',
  'docs-site/docs/en/deployment/manual-install.md'
]) {
  const manual = read(path)
  requireText(manual, '${PACKAGE}.sha256', path)
  requireText(manual, 'sha256sum -c', path)
  requireText(manual, '/opt/incudal/releases/.next-current', path)
}

for (const path of [
  'docs-site/docs/deployment/systemd.md',
  'docs-site/docs/en/deployment/systemd.md'
]) {
  const systemd = read(path)
  rejectText(systemd, 'ExecStartPre=cd ', path)
  requireText(systemd, "ExecStartPre=/usr/bin/bash -lc", path)
}

const config = read('docs-site/docs/.vitepress/config.ts')
requireText(config, "const siteOrigin = 'https://masta-lee.github.io/mastaincus'", 'VitePress config')
requireText(config, "base: '/mastaincus/'", 'VitePress config')
requireText(config, 'transformHead({ pageData })', 'VitePress config')
requireText(config, 'hostname: `${siteOrigin}/`', 'VitePress config')

const changelogGenerator = read('docs-site/scripts/generate-changelog.mjs')
requireText(changelogGenerator, "--format=%H%x09%cs%x09%s", 'changelog generator')
requireText(changelogGenerator, 'fullHash.slice(0, 9)', 'changelog generator')
requireText(changelogGenerator, 'normalizeEmbeddedReleaseNoteHeadings', 'changelog generator')
for (const path of ['docs-site/docs/release/version-log.md', 'docs-site/docs/en/release/version-log.md']) {
  const generated = read(path)
  if (/https:\/\/github\.com\/mastalee928\/payincus\/(?:blob|tree)\//i.test(generated)) {
    throw new Error(`${path}: regenerated source links still point to the retired repository`)
  }
}
const operations = read('OPERATIONS_HANDOFF.md')
requireText(operations, 'SYSTEM_UPDATE_RELEASE_REPOSITORY=masta-lee/mastaincus', 'operations handoff')
requireText(operations, 'INCUDAL_AGENT_RELEASE_REPOSITORY=masta-lee/mastaincus', 'operations handoff')
rejectText(operations, 'SYSTEM_UPDATE_RELEASE_REPOSITORY=mastalee928/payincus', 'operations handoff')
rejectText(operations, 'INCUDAL_AGENT_RELEASE_REPOSITORY=mastalee928/payincus', 'operations handoff')

if (existsSync(resolve(repoRoot, 'docs-site/docs/public/CNAME'))) {
  throw new Error('Repository Pages must not claim an upstream custom domain')
}

const robots = read('docs-site/docs/public/robots.txt')
requireText(robots, 'Sitemap: https://masta-lee.github.io/mastaincus/sitemap.xml', 'robots.txt')

const workflow = read('.github/workflows/docs-pages.yml')
requireText(workflow, '- main', 'docs workflow')
rejectText(workflow, "- 'v*'", 'docs workflow')
requireText(workflow, 'check:deployment', 'docs workflow')

console.log('Deployment documentation guards passed.')
