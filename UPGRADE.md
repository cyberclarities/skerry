# Upgrading Skerry

One script does the whole upgrade: back up, pull the new code, rebuild on fresh base images, restart, and check that the new version answers. If the check fails, it puts the old version back on its own.

```bash
cd /opt/skerry
scripts/upgrade.sh --check     # what is running, what is waiting; changes nothing
scripts/upgrade.sh             # do it
```

Expect a few seconds offline while the containers restart. The build runs first, while the old version is still serving.

---

## 1. Before you start

- **Run it as the user who owns the install folder**, and make sure that user can run `docker` (in the `docker` group). Running with `sudo` makes git refuse the folder as "dubious ownership" on most hosts.
- **The database must be SQLite under `/app/data`**, which is how Skerry ships. With any other `DATABASE_URL`, the script stops and points you to the manual steps in `ADMIN_GUIDE.md` 10.1.
- **Free space.** Each run keeps a copy of the database and the old images. On a large Spotlight tenant the database can run to hundreds of megabytes. See [Cleaning up](#9-cleaning-up).
- **`curl` on the host** lets the script check the site through Caddy, the way a browser reaches it. Without curl it checks only inside the container, and says so.
- **Read `--check` first.** It shows the release notes for everything you are about to take.

## 2. What it does

| Step | What happens | Why |
|---|---|---|
| Preflight | Docker reachable, `.env` present, a web container exists, nothing else upgrading | Stops before touching anything if the basics are wrong. |
| 1. Back up | Database copied with SQLite's backup function and integrity-checked. `.env` and Caddy's CA volume copied. | The database copy is consistent even mid-write. Caddy's CA is what workstations trust; losing it means re-trusting every machine. |
| 2. Rollback point | Current images tagged `skerry-rollback/web:STAMP` and `skerry-rollback/caddy:STAMP` | A rebuild replaces the image under its name. The tag keeps the old one. |
| 3. Code | `git pull --ff-only`. Refuses if tracked files have local edits. | Fast-forward only, so it never makes a merge on the server. |
| Release notes | Prints the CHANGELOG entries between the old and new version. Stops if any lists a step beyond a rebuild. | Some releases need a setting added before the restart. See [section 4](#4-release-notes-and-upgrade-steps). |
| 4. Rebuild | `docker compose build --pull web`, then `docker compose pull caddy`, then `up -d` | `--pull` fetches the current Python and Alpine base. Without it, Docker reuses whatever base it cached on the first build, possibly years ago. |
| 5. Verify | Waits for the health check, compares the running version to the code, then requests `/health` through Caddy | Proves the new version is the one serving, not just that a container started. |
| Rollback | If step 5 fails, puts back the old images and checks them | The database is left alone. Releases only add tables, and the old version ignores a table it does not know. |

Every run writes a log and a before-and-after record. See [section 8](#8-where-things-land).

## 3. What you will see

A good run ends like this:

```
== Done
                 before                     after
app_version      1.7.4                      1.8
git_commit       270bad5                    dd6aaa7
web_alpine       3.21.10                    3.24.4
web_python       3.12.9                     3.12.16
gunicorn         22.0.0                     26.2.0
caddy_version    v2.10.2                    v2.11.9
caddy_alpine     3.21.10                    3.24.4

Backups and logs: /opt/skerry/backups/upgrade_20261106_220843
To undo: scripts/upgrade.sh --rollback 20261106_220843
```

Then sign in and look at the version under the logo. If you use SSO, sign in with SSO; the health check does not cover it.

## 4. Release notes and upgrade steps

Every CHANGELOG entry ends with an `### Upgrading` section. The script reads it.

A routine release says:

```
### Upgrading
- Rebuild: `docker compose up -d --build`. No settings change.
```

The script passes that by. Anything else in that section, such as a new `.env` setting or a one-time command, makes it stop before the rebuild:

- **At a terminal,** it shows the step and asks whether you have done it. Answer no, and it stops with the old version still running.
- **With `--yes`,** it always stops. Whoever scheduled an unattended run has not read the notes.

Either way, the code is already pulled. Do the step, then carry on with:

```bash
scripts/upgrade.sh --no-pull
```

**For whoever writes the release:** use the routine wording above exactly when nothing else is needed, so a step that matters is never buried in routine text. Put anything that must happen before the restart in its own bullet.

## 5. If it fails

The script says where it stopped and what state it left. In short:

| Stopped at | State | Do this |
|---|---|---|
| Preflight | Nothing changed | Fix what it names. |
| Back up | Nothing changed | Usually disk space or a missing database file. The message carries the error. |
| Local changes | Backups taken; nothing else changed | Commit or stash the edits, or re-run with `--no-pull` to build what is in the folder. |
| Cannot fast-forward | Backups taken; nothing else changed | The branch has moved in a way that needs a person. Sort it out with git, then re-run. |
| Upgrade steps | Code pulled; old version still running | Do the steps, then `scripts/upgrade.sh --no-pull`. |
| Build failed | Code pulled; old version still running | Read the build output. To return the folder to the old code, run the `git reset --hard` it prints. |
| Verify failed, rolled back | Old version running; folder holds the new code | `docker compose logs web` shows why the new one failed. Run the printed `git reset --hard` so a later rebuild does not bring it back. |
| Verify failed, rollback failed too | Not serving | `docker compose logs web`, then [section 7](#7-restore-by-hand). |
| Another upgrade running | Nothing changed | If none is, an earlier run was killed. Remove `backups/.upgrade.lock` and re-run. |

## 6. Rolling back later

Something wrong with the new version a day later:

```bash
scripts/upgrade.sh --check                       # lists rollback points
scripts/upgrade.sh --rollback 20261106_220843
```

That puts back the images from that run and checks them. The database stays as it is, with everything entered since.

To also put back the database as it was before that upgrade:

```bash
scripts/upgrade.sh --rollback 20261106_220843 --restore-db
```

**This throws away everything entered since that backup.** The current database is set aside in the backup folder first, under `pre-restore-STAMP/`, so it can be recovered. Use it only when the new version damaged data, not just because it misbehaved.

Afterward, the script prints a `git reset --hard` to bring the folder back in line with what is running. Run it. Otherwise the next `docker compose up --build` rebuilds the newer code.

## 7. Restore by hand

When the script cannot help, for example when the rollback images were pruned. From the install folder:

```bash
STAMP=20261106_220843
B=backups/upgrade_$STAMP
docker compose down

# Database: set the current one and its journal aside, put the backup in.
mkdir -p "$B/pre-restore-manual"
sudo mv data/risk_register.db "$B/pre-restore-manual/"
sudo mv data/risk_register.db-journal "$B/pre-restore-manual/" 2>/dev/null || true
sudo cp "$B/risk_register.db" data/

# Images, if the rollback tags still exist. `docker compose images` shows the
# names Compose uses; skerry-web assumes the folder is named skerry.
docker tag skerry-rollback/web:$STAMP skerry-web
docker tag skerry-rollback/caddy:$STAMP caddy:alpine

# Caddy's CA, only if the volume was lost.
docker run --rm -v skerry_caddy_data:/data -v "$PWD/$B:/backup" alpine \
    sh -c 'cd / && tar xzf /backup/caddy_data.tgz'

docker compose up -d --no-build
```

The `.env` from that day is `$B/env.backup`. Compare it with `diff .env "$B/env.backup"` before copying it back.

## 8. Where things land

Each run gets its own folder, `backups/upgrade_STAMP/`:

| File | What it is |
|---|---|
| `risk_register.db` | The database, integrity-checked |
| `env.backup` | `.env` from before the upgrade. **Holds every secret Skerry uses.** Mode 600. |
| `caddy_data.tgz` | Caddy's CA and certificates |
| `rollback.env` | The image IDs and version the rollback uses |
| `state-before.txt`, `state-after.txt` | Versions of everything that matters, before and after |
| `pip-freeze-before.txt`, `pip-freeze-after.txt` | Every Python package in the running image |
| `upgrade.log` | The full run |

`backups/` is in `.gitignore` and `.dockerignore`, so none of this reaches git or an image. It is still on the same host as the thing it backs up. Copy the database and `env.backup` off the host as you would any backup (`ADMIN_GUIDE.md` 9).

## 9. Cleaning up

Old runs pile up. Keep the last few:

```bash
# Rollback images
docker image ls skerry-rollback/web
docker image rm skerry-rollback/web:20261001_090000 skerry-rollback/caddy:20261001_090000

# Backup folders
rm -rf backups/upgrade_20261001_090000
```

The script mentions it once there are more than three rollback images.

## 10. Zip installs

With no git checkout, the script skips the pull. Extract the new release over the install folder first, keeping `.env`, `data/`, and `backups/`, then:

```bash
scripts/upgrade.sh --no-pull
```

## 11. Security updates with no new release

Run the script even when no new code is waiting. It rebuilds on the current Python and Alpine base images and pulls the current Caddy, which is how operating system and Caddy fixes reach a running install. Docker does neither by itself. Once a month is reasonable:

```bash
# crontab -e, as the folder owner. Sunday 03:30.
30 3 * * 0 cd /opt/skerry && scripts/upgrade.sh --yes >> backups/cron.log 2>&1
```

Run it once by hand before scheduling it; that creates `backups/`, where the cron log goes. Unattended runs stop safely at any release that lists an upgrade step (section 4), so a scheduled run never applies a release that needs a person.

## 12. For maintainers: shipping a dependency update

When `requirements.txt`, the base images, or the CDN libraries change:

1. Change the pins. Run the test suite under Python 3.12, the container's version.
2. Bump the version and write the CHANGELOG entry, with its `### Upgrading` section (section 4).
3. On a test host, or a copy of production, run `scripts/upgrade.sh` and confirm the summary shows what you meant to change.
4. Regenerate `SBOM.md` from `pip-freeze-after.txt` and `state-after.txt` from that run. Those record what is actually in the image, not what the pins say.
5. Commit and push. Production then upgrades with the same script.
