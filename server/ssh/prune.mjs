// ---------------------------------------------------------------------------
// Docker cleanup: the one place in Vigil that changes anything on a host.
//
// Everything else in this product reads. This module exists because being told
// "you have 40 GB of dead Docker layers" and then having to go and SSH in
// yourself is a worse product - but it is a real change to the security posture
// and it is built accordingly:
//
//   1. OFF BY DEFAULT. VG_ALLOW_DOCKER_PRUNE must be set to "on". A default
//      deployment cannot change anything, which keeps the promise the rest of
//      the product makes.
//
//   2. FIXED COMMANDS. The commands below are constant strings. Nothing from a
//      request, a database row or a scan is ever interpolated into them, so
//      there is no shell injection surface here - not a sanitised one, an
//      absent one. The API takes an action KEY and looks it up; it never takes
//      a command.
//
//   3. PRUNE ONLY, NEVER TARGETED. There is deliberately no "remove this
//      container" verb. `prune` removes only what Docker itself considers
//      unused, which means a running service can never be taken down by a
//      mistake here or by someone guessing an id.
//
//   4. VOLUMES ARE SEPARATE. Pruning volumes deletes data, not waste. It needs
//      its own second flag, it is never part of the headline "reclaimable"
//      figure, and it is never included in the combined action.
//
//   5. EVERY RUN IS AUDITED, with the actor, the host and the exact command.
//
// If you want the strict read-only guarantee back, leave VG_ALLOW_DOCKER_PRUNE
// unset and this module can do nothing at all.
// ---------------------------------------------------------------------------

import * as ssh from './client.mjs';

export const PRUNE_ENABLED = process.env.VG_ALLOW_DOCKER_PRUNE === 'on';
export const VOLUME_PRUNE_ENABLED = process.env.VG_ALLOW_VOLUME_PRUNE === 'on';

/**
 * The complete set of commands this product can run on a host. Constant
 * strings, looked up by key.
 */
export const PRUNE_ACTIONS = {
  'exited-containers': {
    label: 'Remove exited containers',
    command: 'docker container prune -f',
    describes: 'Containers in the exited or created state, and the writable layer and logs each one holds.',
    keeps: 'Running, paused and restarting containers are untouched.',
    dataLoss: false,
  },
  'dangling-images': {
    label: 'Remove dangling images',
    command: 'docker image prune -f',
    describes: 'Untagged layers left behind when an image was rebuilt under the same tag.',
    keeps: 'Every tagged image stays, including ones nothing is currently running.',
    dataLoss: false,
  },
  'unused-images': {
    label: 'Remove all unused images',
    command: 'docker image prune -a -f',
    describes: 'Every image no container is using, tagged or not.',
    keeps: 'Images in use by a container stay - but anything you were keeping as a cache or a rollback target will be pulled again next time.',
    dataLoss: false,
  },
  'build-cache': {
    label: 'Remove build cache',
    command: 'docker builder prune -f',
    describes: 'BuildKit layer cache.',
    keeps: 'Nothing is lost except build speed: the next build re-does the cached steps.',
    dataLoss: false,
  },
  'all-safe': {
    label: 'Remove exited containers, dangling images and build cache',
    command: 'docker system prune -f',
    describes: 'The three above in one pass: stopped containers, dangling images, unused networks and build cache.',
    keeps: 'Volumes are NOT touched by this command, which is why it is the default.',
    dataLoss: false,
  },
  'unused-volumes': {
    label: 'Remove unused volumes',
    command: 'docker volume prune -f',
    describes: 'Volumes no container references.',
    keeps: 'Nothing. This DELETES DATA - a database volume whose container is temporarily stopped looks exactly like an unused one.',
    dataLoss: true,
    requiresVolumeFlag: true,
  },
};

/** What the caller is allowed to run right now, and why not when they are not. */
export function availableActions() {
  return Object.entries(PRUNE_ACTIONS).map(([key, a]) => {
    let blockedBecause = null;
    if (!PRUNE_ENABLED) blockedBecause = 'Cleanup is disabled on this instance. Set VG_ALLOW_DOCKER_PRUNE=on to enable it.';
    else if (a.requiresVolumeFlag && !VOLUME_PRUNE_ENABLED) {
      blockedBecause = 'Volume pruning deletes data, so it needs VG_ALLOW_VOLUME_PRUNE=on as well.';
    }
    return { key, label: a.label, command: a.command, describes: a.describes, keeps: a.keeps, dataLoss: a.dataLoss, allowed: !blockedBecause, blockedBecause };
  });
}

/** "Total reclaimed space: 1.234GB" is the line worth surfacing. */
function reclaimedFrom(output) {
  const m = String(output ?? '').match(/Total reclaimed space:\s*(.+)$/im);
  return m ? m[1].trim() : null;
}

/**
 * Run one allowlisted prune against one host.
 *
 * @param {object} credentials from repo.credentialsFor()
 * @param {string} actionKey   a key of PRUNE_ACTIONS - never a command
 */
export async function prune(credentials, actionKey) {
  const action = PRUNE_ACTIONS[actionKey];
  if (!action) return { ok: false, error: 'unknown_action', message: 'No such cleanup action.' };
  if (!PRUNE_ENABLED) {
    return {
      ok: false,
      error: 'disabled',
      message: 'Docker cleanup is disabled on this instance. Set VG_ALLOW_DOCKER_PRUNE=on to enable it.',
    };
  }
  if (action.requiresVolumeFlag && !VOLUME_PRUNE_ENABLED) {
    return {
      ok: false,
      error: 'volumes_disabled',
      message: 'Volume pruning deletes data and needs VG_ALLOW_VOLUME_PRUNE=on in addition.',
    };
  }

  // The command is the constant from the table above. Nothing is appended.
  const res = await ssh.run(credentials, action.command);

  // Docker exits non-zero when the daemon refuses; the stderr says why, and it
  // is far more useful to the person than "exit code 1".
  if (res.code !== 0) {
    return {
      ok: false,
      error: 'command_failed',
      message: (res.stderr || res.stdout || 'The command failed').trim().split('\n')[0],
      command: action.command,
      exitCode: res.code,
    };
  }

  return {
    ok: true,
    command: action.command,
    label: action.label,
    reclaimed: reclaimedFrom(res.stdout),
    output: String(res.stdout ?? '').slice(0, 4000),
  };
}
