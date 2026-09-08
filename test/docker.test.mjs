// Docker parsing, rules and the cleanup allowlist.
//
// The fixtures are real `docker` output. The two things worth pinning down are
// the unit maths (docker mixes base-1000 and base-1024 in different
// subcommands, and getting it wrong misstates reclaimable space by 7-10%) and
// the allowlist, which is the only write path in the product.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseDockerSize, parseDockerDf, parseDockerContainers, parseDockerImages, parseDockerVolumes } from '../server/ssh/parse.mjs';
import { assembleFacts } from '../server/ssh/probe.mjs';
import { evaluate } from '../server/engine/checks.mjs';
import { PRUNE_ACTIONS, availableActions, prune } from '../server/ssh/prune.mjs';

const GiB = 1024 ** 3;

/* ------------------------------------------------------------------- sizes */

test('docker size strings, in both unit families', () => {
  assert.equal(parseDockerSize('0B'), 0);
  assert.equal(parseDockerSize('435.7MB'), 435700000, 'system df uses base 1000');
  assert.equal(parseDockerSize('1.2GB'), 1200000000);
  assert.equal(parseDockerSize('2GiB'), 2 * 1024 ** 3, 'and GiB is base 1024');
  assert.equal(parseDockerSize('1.09kB (virtual 72.8MB)'), 1090, 'takes the first figure, not the virtual size');
  assert.equal(parseDockerSize('1.234GB (75%)'), 1234000000, 'reclaimable carries a percentage suffix');
  assert.equal(parseDockerSize(''), null);
  assert.equal(parseDockerSize('n/a'), null, 'unparseable is null, never zero');
});

/* ---------------------------------------------------------------- system df */

test('system df is the source of truth for reclaimable space', () => {
  const df = parseDockerDf(
    [
      'Images\t24\t6\t8.412GB\t5.921GB (70%)',
      'Containers\t31\t5\t1.204GB\t1.102GB (91%)',
      'Local Volumes\t9\t3\t2.5GB\t1.9GB (76%)',
      'Build Cache\t142\t0\t3.8GB\t3.8GB',
    ].join('\n')
  );
  assert.equal(df.images.total, 24);
  assert.equal(df.images.active, 6);
  assert.equal(df.images.reclaimableBytes, 5921000000);
  assert.equal(df['local-volumes'].reclaimableBytes, 1900000000);
  assert.equal(df['build-cache'].reclaimableBytes, 3800000000);
});

/* --------------------------------------------------------------- containers */

test('container states, health and exit codes', () => {
  const c = parseDockerContainers(
    [
      'a1b2c3\tapi\tregistry/api:1.4\trunning\tUp 3 days (healthy)\t3 days ago\t1.09kB',
      'd4e5f6\tworker\tregistry/worker:2.1\trestarting\tRestarting (1) 4 seconds ago\t2 days ago\t512B',
      'g7h8i9\tmigrate\tregistry/api:1.4\texited\tExited (0) 3 weeks ago\t3 weeks ago\t0B',
      'j1k2l3\tcache\tredis:7\trunning\tUp 6 hours (unhealthy)\t6 hours ago\t0B',
    ].join('\n')
  );
  assert.equal(c.length, 4);
  assert.equal(c[0].healthy, true);
  assert.equal(c[1].state, 'restarting');
  assert.equal(c[2].exitCode, 0);
  assert.equal(c[3].healthy, false, 'a container can be Up and unhealthy at the same time');
  assert.equal(c[0].healthy !== null && c[2].healthy, null, 'no health check configured is null, not unhealthy');
});

test('images: dangling is <none>, in either field', () => {
  const i = parseDockerImages(
    [
      'aaa111\tregistry/api\t1.4\t412MB\t2024-03-01 10:00:00 +0000 UTC',
      'bbb222\t<none>\t<none>\t388MB\t2024-02-14 09:00:00 +0000 UTC',
      'ccc333\tregistry/api\t<none>\t401MB\t2024-02-01 09:00:00 +0000 UTC',
    ].join('\n')
  );
  assert.equal(i[0].dangling, false);
  assert.equal(i[1].dangling, true);
  assert.equal(i[2].dangling, true, 'a tagged repo with an untagged tag is still dangling');
  assert.equal(i[0].name, 'registry/api:1.4');
  assert.equal(i[1].name, 'bbb222', 'an untagged image is identified by its id');
});

test('volumes', () => {
  const v = parseDockerVolumes('pgdata\tlocal\nb3f1e9c\tlocal');
  assert.equal(v.length, 2);
  assert.equal(v[0].name, 'pgdata');
});

/* ------------------------------------------------------------ fact assembly */

function probeOutput(sections) {
  return Object.entries(sections)
    .map(([k, v]) => '@@VG:' + k + '@@\n' + v)
    .join('\n');
}

const DOCKER_SECTIONS = {
  dockersrc: 'ok',
  dockerversion: '25.0.3',
  dockerroot: '/var/lib/docker',
  dockerdf: ['Images\t24\t6\t8.412GB\t5.921GB (70%)', 'Containers\t31\t5\t1.204GB\t1.102GB (91%)', 'Local Volumes\t9\t3\t2.5GB\t1.9GB (76%)', 'Build Cache\t142\t0\t3.8GB\t3.8GB'].join('\n'),
  dockerps: [
    'a1\tapi\tregistry/api:1.4\trunning\tUp 3 days (healthy)\t3 days ago\t1.09kB',
    'd4\tworker\tregistry/worker:2.1\trestarting\tRestarting (1) 4 seconds ago\t2 days ago\t512B',
    ...Array.from({ length: 8 }, (_, i) => 'x' + i + '\tjob-' + i + '\tregistry/job:1\texited\tExited (0) 2 weeks ago\t2 weeks ago\t0B'),
  ].join('\n'),
  dockerimages: [
    'aaa\tregistry/api\t1.4\t412MB\t2024-03-01 10:00:00 +0000 UTC',
    'bbb\t<none>\t<none>\t1.4GB\t2024-02-14 09:00:00 +0000 UTC',
  ].join('\n'),
  dockervolumes: 'pgdata\tlocal\nb3f1e9c\tlocal',
  dockervolumesdangling: 'b3f1e9c',
};

test('docker facts assemble, with volumes kept out of the headline', () => {
  const { facts } = assembleFacts(probeOutput(DOCKER_SECTIONS));
  const d = facts.docker;

  assert.equal(d.installed, true);
  assert.equal(d.accessible, true);
  assert.equal(d.version, '25.0.3');
  assert.equal(d.containers.running, 1);
  assert.equal(d.containers.restarting, 1);
  assert.equal(d.containers.exited, 8);
  assert.equal(d.images.dangling, 1);
  assert.equal(d.volumes.dangling, 1);

  // images + containers + build cache, deliberately NOT volumes.
  assert.equal(d.reclaimableBytes, 5921000000 + 1102000000 + 3800000000);
  assert.equal(d.reclaimableWithVolumesBytes, d.reclaimableBytes + 1900000000);
});

test('docker absent and docker refused are different answers', () => {
  const absent = assembleFacts(probeOutput({ dockersrc: 'none' }));
  assert.equal(absent.facts.docker, null, 'no docker means nothing to say');
  assert.ok(!absent.limited.includes('docker'));

  const denied = assembleFacts(probeOutput({ dockersrc: 'denied' }));
  assert.equal(denied.facts.docker.installed, true);
  assert.equal(denied.facts.docker.accessible, false);
  assert.ok(denied.limited.includes('docker'), 'an unknown amount of cleanup is not zero cleanup');
});

/* -------------------------------------------------------------------- rules */

function factsWithDocker(overrides = {}, diskOverride) {
  const { facts } = assembleFacts(probeOutput({ ...DOCKER_SECTIONS, ...overrides }));
  return {
    ...facts,
    disks: diskOverride ?? [{ filesystem: '/dev/sda1', mount: '/', totalBytes: 200 * GiB, usedBytes: 60 * GiB, availBytes: 140 * GiB, usedPct: 30, inodesUsedPct: 10 }],
    memory: null,
    cpu: { cores: null, loadPerCore: null },
    updates: null,
    services: { failed: [], systemState: null },
    security: { sshd: {}, authFailures24h: null },
    time: { ntpSynchronized: null, skewSeconds: null },
    host: { os: null, uptimeSeconds: 3600 },
    reboot: { required: false, kernelStale: false },
    ports: [],
    processes: { zombies: 0 },
  };
}

const find = (f, key) => f.find((x) => x.key === key);

test('a restarting container is critical, and names itself', () => {
  const f = evaluate(factsWithDocker());
  const r = find(f, 'docker:restarting');
  assert.equal(r.severity, 'critical');
  assert.match(r.title, /stuck restarting/);
  assert.match(r.evidence.find((e) => e.label === 'Containers').value, /worker/);
  assert.match(r.remedy, /docker logs/);
});

test('an unhealthy-but-running container is reported separately from a restarting one', () => {
  const f = evaluate(
    factsWithDocker({
      dockerps: 'j1\tcache\tredis:7\trunning\tUp 6 hours (unhealthy)\t6 hours ago\t0B',
    })
  );
  assert.equal(find(f, 'docker:unhealthy').severity, 'critical');
  assert.equal(find(f, 'docker:restarting'), undefined);
});

test('reclaimable space is judged against the disk it sits on', () => {
  // ~10.8 GB reclaimable on a roomy 200 GiB disk: a warning.
  const roomy = evaluate(factsWithDocker());
  assert.equal(find(roomy, 'docker:reclaimable').severity, 'warning');

  // The same bytes on a 30 GiB disk that is 92% full: critical, because now it
  // is the difference between a working host and a full one.
  const tight = evaluate(
    factsWithDocker({}, [{ filesystem: '/dev/sda1', mount: '/', totalBytes: 30 * GiB, usedBytes: 27 * GiB, availBytes: 3 * GiB, usedPct: 92, inodesUsedPct: 10 }])
  );
  const t = find(tight, 'docker:reclaimable');
  assert.equal(t.severity, 'critical');
  assert.match(t.detail, /92% full/);
});

test('a tidy Docker host raises nothing', () => {
  const f = evaluate(
    factsWithDocker({
      dockerdf: 'Images\t3\t3\t900MB\t0B (0%)\nContainers\t3\t3\t20MB\t0B (0%)\nLocal Volumes\t2\t2\t400MB\t0B (0%)\nBuild Cache\t0\t0\t0B\t0B',
      dockerps: 'a1\tapi\tregistry/api:1.4\trunning\tUp 3 days (healthy)\t3 days ago\t1.09kB',
      dockerimages: 'aaa\tregistry/api\t1.4\t412MB\t2024-03-01 10:00:00 +0000 UTC',
      dockervolumesdangling: '',
    })
  );
  assert.equal(f.filter((x) => x.category === 'Docker').length, 0);
});

test('exited containers are reported, but only once there are enough to matter', () => {
  const many = evaluate(factsWithDocker());
  assert.ok(find(many, 'docker:exited'), '8 exited containers is worth mentioning');

  const few = evaluate(
    factsWithDocker({ dockerps: 'x0\tjob\tregistry/job:1\texited\tExited (0) 2 weeks ago\t2 weeks ago\t0B' })
  );
  assert.equal(find(few, 'docker:exited'), undefined, 'one exited container is normal');
});

test('no docker means no docker findings at all', () => {
  const f = evaluate(factsWithDocker({ dockersrc: 'none', dockerdf: '', dockerps: '', dockerimages: '' }));
  assert.equal(f.filter((x) => x.category === 'Docker').length, 0);
});

/* --------------------------------------------------------------- allowlist */

test('every cleanup action is a constant string with nothing interpolable', () => {
  for (const [key, a] of Object.entries(PRUNE_ACTIONS)) {
    assert.match(a.command, /^docker (container|image|builder|system|volume) prune( -a)? -f$/, key + ' has an unexpected shape');
    assert.ok(!/[;&|`$><]/.test(a.command), key + ' contains shell metacharacters');
    assert.ok(a.command.includes('prune'), key + ' is not a prune');
  }
});

test('there is no way to target a specific container or image', () => {
  // A targeted rm could take down a running service; prune cannot, because
  // Docker itself decides what counts as unused.
  const commands = Object.values(PRUNE_ACTIONS).map((a) => a.command).join(' ');
  assert.ok(!/\brm\b/.test(commands));
  assert.ok(!/\bstop\b/.test(commands));
  assert.ok(!/\bkill\b/.test(commands));
  assert.ok(!/\bexec\b/.test(commands));
});

test('only volume pruning is marked as destroying data', () => {
  const destructive = Object.entries(PRUNE_ACTIONS).filter(([, a]) => a.dataLoss).map(([k]) => k);
  assert.deepEqual(destructive, ['unused-volumes']);
});

test('cleanup is refused unless it has been explicitly enabled', async () => {
  // VG_ALLOW_DOCKER_PRUNE is unset in the test environment, which is the
  // default a fresh deployment runs with.
  const res = await prune({ host: 'x', username: 'y', privateKey: 'z' }, 'all-safe');
  assert.equal(res.ok, false);
  assert.equal(res.error, 'disabled');

  for (const a of availableActions()) {
    assert.equal(a.allowed, false, a.key + ' should be blocked by default');
    assert.match(a.blockedBecause, /VG_ALLOW_DOCKER_PRUNE/);
  }
});

test('an unknown action is refused before anything is looked up', async () => {
  const res = await prune({ host: 'x' }, 'rm -rf /');
  assert.equal(res.ok, false);
  assert.equal(res.error, 'unknown_action');
});
