# Container image

The `container-image` job builds the `statichcpd` image from the trixie
package that `debian-trixie-build` produced in the same pipeline
(`workdir/statichcpd_<version>~deb13_amd64.deb`). `docker/ci-image.sh` does
the work. The base is `debian:trixie-slim`, the latest one (`BASE_IMAGE`
in the Dockerfile). apt installs the package's dependencies from the Debian
archive; the image uses nothing from repo.pb.local. The .deb is
bind-mounted for the install step only, so no layer of the image holds it.

## When it runs and what it pushes

The job takes the rules of `debian-trixie-build`. It runs in branch
pipelines of master/main, dev* and feature/*, and in merge request
pipelines into those branches. It never runs in tag pipelines, where the
recipe builds no packages.

Its `needs` decide when it starts, not its stage. It waits for
`debian-trixie-lintian`, and in branch pipelines that upload, for
`debian-trixie-upload`. So a branch pipeline pushes an image only for a
package that passed lintian and was uploaded. Branch pipelines upload when
`UPLOAD_TO_REPOSITORY` is "true", the recipe's default. The job sits in the
recipe's "upload" stage, before "cleanup artifacts", which deletes the
packages. `debian/gitlab-ci.yml` adds no stages list of its own: one would
replace the recipe's.

Each run builds the image and runs two smoke tests in it, with no network:

- `python3 -m statichcpd --help`;
- `python3 -m statichcpd -f -a /etc/statichcpd/ --init-db-and-exit`, which
  reads the config files and the attribute CSVs, as a start does, and
  creates the database schema. Releases up to 3.09 do not have the flag,
  and the job skips this test for them.

A merge request pipeline stops there. A branch pipeline also pushes the
image, as `<PF_HARBOR_REGISTRY_URL>/statichcpd`, if the three variables
below are set:

| Branch | Tags |
|---|---|
| master, main | `<version>`, `latest` |
| dev* | `<version>`, `develop` |
| any other (feature/*) | `<version>` |

`<version>` is the package version without `~deb13`, with each character
outside `A-Za-z0-9_.-` replaced by `-`. That gives `3.09` on master, the
same as the release's git tag, and `3.09-develop-20260625.0915-50e29092` on
develop. The job pushes `<version>` and then points `latest` or `develop`
at the same digest in the registry (`docker buildx imagetools create`). The
image has no provenance attestation, so each tag is a plain image manifest.
If two pipelines of one branch push at once, the moving tag ends at the one
that finishes last. On master the job pushes once the package is in the
proposed suite, before `package-approve`: `latest` can point to a package
that is not approved yet.

## CI variables

| Variable | Value |
|---|---|
| `PF_HARBOR_REGISTRY_URL` | registry host and project, e.g. `harbor.infra.cluster.ionos.com/<project>`; a scheme such as `https://` is ignored |
| `PF_HARBOR_REGISTRY_USER` | a Harbor robot account that can push to that project |
| `PF_HARBOR_REGISTRY_PASSWORD` | the robot account's secret |

Set them on the project or on the sdn group. Make all three protected, so
that only protected branches push. Mask the password. Robot account names
contain `$` (`robot$<project>+<name>`), so clear "Expand variable
reference" on the user variable. Without these variables the job still
builds and tests the image.

## Runner

The job has no tags and no services. It needs a Docker executor that
mounts the host's Docker socket into the job, as buildchain's own image
job does. It uses no docker-in-docker and no privileged mode.

The daemon must reach Docker Hub, for the job image, the base image and the
`docker/dockerfile:1` frontend, each the latest one, and
deb.debian.org.

The daemon is shared with other jobs, so the job gives it only names that
no other job uses: the build tag `ci/statichcpd:<pipeline id>-<job id>`,
and the version tag it pushes. The script removes the version tag, and
`after_script` the build tag. `latest` and `develop` are names that all
pipelines share, so they never exist on the daemon: the job sets them in
the registry, from the job container. That container must reach the
registry itself, over HTTPS. The login uses a client config of the job's
own, which the script deletes. The build uses no layer cache: on a shared
daemon, a cached `apt-get` layer would keep old packages.

Without the host's socket, the job fails at `docker build`. With no runner
for untagged jobs, the job stays pending, and "cleanup artifacts" waits for
it. The package uploads never wait for this job. A retry after the
pipeline has ended finds no .deb, because "cleanup artifacts" has deleted
it: run a new pipeline.

## Building it locally

Put a trixie build of statichcpd in a directory and run, from the
repository root:

    WORKDIR=/path/to/that/dir sh docker/ci-image.sh

This builds `ci/statichcpd:local` and runs the smoke tests. Without
`CI_COMMIT_BRANCH` and the `PF_HARBOR_REGISTRY_*` variables it does not
push. `BASE_IMAGE` and the proxy variables (`http_proxy`, `https_proxy`,
`no_proxy` and their upper-case forms) are passed to the build when they
are set.

## Running it

- The entrypoint is `python3 -m statichcpd` and the command is
  `-a /etc/statichcpd/`, the unit's `OPTIONS`.
- Run it on the host network, as root, with `NET_RAW` added: it serves DHCP
  on raw packet sockets and binds UDP 67 and 547.
- Mount `/var/lib/statichcpd`. It holds the sqlite database that pbsdnmgr
  writes. The daemon creates the schema when it starts;
  `--init-db-and-exit` does only that.
- Mount `/dev/log`. The daemon logs only to syslog; with `-f` it also logs
  to stderr.
- Stop it with SIGINT, the image's stop signal. On SIGINT it closes the
  database and exits.
- It reads `/etc/statichcpd/statichcpd.conf`, then every `*.conf` file in
  `/etc/statichcpd/`. On a host, `statichcpd_override.conf` in that
  directory (served interface regex, DHCPv6 timers, database path) comes
  from the pbsdnmgr package, not from this one. The image does not have it,
  so mount it to get the same settings.
