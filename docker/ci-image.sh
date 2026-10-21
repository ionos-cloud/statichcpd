#!/bin/sh
# Builds the statichcpd image from the trixie .deb of this pipeline's
# debian-trixie-build job, smoke-tests it, and pushes it to Harbor from
# branch pipelines when PF_HARBOR_REGISTRY_URL, _USER and _PASSWORD are set.
# Runs from the repository root; see docker/README.md.
#
# Locally: WORKDIR=<dir with the .deb> sh docker/ci-image.sh
# builds and smoke-tests ci/statichcpd:local and does not push.

set -eu

package=statichcpd
arch=amd64
image=${IMAGE_NAME:-$package}
workdir=${WORKDIR:-workdir}
here=$(cd "$(dirname "$0")" && pwd)

say() {
  echo "ci-image: $*"
}

fail() {
  echo "ci-image: $*" >&2
  exit 1
}

# True when the variable named $1 is set and not empty.
is_set() {
  eval "[ -n \"\${$1:-}\" ]"
}

# The package from the build job's artifact.
set -- "$workdir/$package"_*~deb13_"$arch".deb
[ -e "$1" ] || fail "no ${package}_*~deb13_$arch.deb in $workdir (the artifact of debian-trixie-build)"
[ "$#" -eq 1 ] || fail "$# $package trixie packages in $workdir, expected one: $*"
deb=$1
deb_file=${deb##*/}
if ! is_set DEB_VERSION; then
  DEB_VERSION=${deb_file#"${package}_"}
  DEB_VERSION=${DEB_VERSION%"_$arch.deb"}
fi

# The daemon is the runner host's and shared: a name no other job uses.
if is_set CI_PIPELINE_ID && is_set CI_JOB_ID; then
  local_tag="ci/$image:$CI_PIPELINE_ID-$CI_JOB_ID"
else
  local_tag="ci/$image:local"
fi

tmp=$(mktemp -d)
remote_tag=
logged_in=
cleanup() {
  if [ -n "$remote_tag" ]; then
    docker image rm "$remote_tag" >/dev/null 2>&1 || true
  fi
  if [ -n "$logged_in" ]; then
    docker logout "$logged_in" || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

mkdir "$tmp/debs"
cp "$here/Dockerfile" "$tmp/"
cp "$deb" "$tmp/debs/"

set -- --pull --tag "$local_tag" --build-arg "DEB_FILE=$deb_file" \
  --label "org.opencontainers.image.version=$DEB_VERSION"
if is_set CI_COMMIT_SHA; then
  set -- "$@" --label "org.opencontainers.image.revision=$CI_COMMIT_SHA"
fi
if is_set CI_PROJECT_URL; then
  set -- "$@" --label "org.opencontainers.image.source=$CI_PROJECT_URL"
fi
# By name only: docker takes the values from the environment, which keeps
# them off the command line.
for v in BASE_IMAGE http_proxy https_proxy no_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY; do
  if is_set "$v"; then
    set -- "$@" --build-arg "$v"
  fi
done

# No provenance attestation, so that every daemon pushes a plain image
# manifest. With the containerd image store, BuildKit would otherwise add
# one and push an image index.
# No layer cache: the daemon is shared, and a cached apt-get layer would
# keep old Debian packages.
say "building $local_tag from $deb_file"
BUILDX_NO_DEFAULT_ATTESTATIONS=1 docker build --no-cache "$@" "$tmp"

say "smoke test: python3 -m statichcpd --help"
help=$(docker run --rm --network none "$local_tag" --help)
printf '%s\n' "$help"

# --init-db-and-exit reads the config files and the attribute CSVs, as a
# start does, and creates the database schema. Releases up to 3.09 do not
# have it. The container has no /dev/log, so every log record also prints
# a "--- Logging error ---" traceback: the output is shown only on failure.
case $help in
  *--init-db-and-exit*)
    say "smoke test: python3 -m statichcpd -f -a /etc/statichcpd/ --init-db-and-exit"
    if ! out=$(docker run --rm --network none --tmpfs /var/lib/statichcpd \
      "$local_tag" -f -a /etc/statichcpd/ --init-db-and-exit 2>&1); then
      printf '%s\n' "$out" >&2
      fail "--init-db-and-exit failed in $local_tag"
    fi
    ;;
  *) say "this statichcpd has no --init-db-and-exit: skipping that smoke test" ;;
esac

# Only branch pipelines push: merge request pipelines have no
# CI_COMMIT_BRANCH. The credentials are protected variables, so only
# protected branches have them.
if ! is_set CI_COMMIT_BRANCH; then
  say "not a branch pipeline: built $local_tag, not pushing"
  exit 0
fi
missing=
for v in PF_HARBOR_REGISTRY_URL PF_HARBOR_REGISTRY_USER PF_HARBOR_REGISTRY_PASSWORD; do
  is_set "$v" || missing="$missing $v"
done
if [ -n "$missing" ]; then
  say "not pushing from $CI_COMMIT_BRANCH, not set:$missing"
  exit 0
fi

# An image tag is [A-Za-z0-9_][A-Za-z0-9_.-]{0,127}.
is_set VERSION || fail "VERSION is not set (the dotenv of the version-* job)"
version_tag=$(printf '%s\n' "$VERSION" | sed 's/[^A-Za-z0-9_.-]/-/g')
case $version_tag in
  [A-Za-z0-9_]*) ;;
  *) fail "VERSION $VERSION does not make an image tag" ;;
esac
[ "${#version_tag}" -le 128 ] || fail "image tag $version_tag is longer than 128 characters"
case $CI_COMMIT_BRANCH in
  master | main) moving=latest ;;
  dev*) moving=develop ;;
  *) moving= ;;
esac

registry=${PF_HARBOR_REGISTRY_URL#*://}
registry=${registry%/}
case $registry in
  ?*/?*) ;;
  *) fail "PF_HARBOR_REGISTRY_URL is not <host>/<project>" ;;
esac
login_host=${registry%%/*}

# A client config of this job's own, removed with $tmp: the credentials
# never land in a shared ~/.docker.
DOCKER_CONFIG=$tmp/docker-config
export DOCKER_CONFIG
printf '%s' "$PF_HARBOR_REGISTRY_PASSWORD" |
  docker login --username "$PF_HARBOR_REGISTRY_USER" --password-stdin "$login_host"
logged_in=$login_host

# Only the version tag goes through the shared daemon: no other pipeline
# builds that version. The moving tag is a name all pipelines share, and a
# concurrent job could retag or remove it on the daemon between our tag and
# our push. So it is set in the registry, from this container, as a copy of
# the version tag's manifest: --prefer-index=false keeps the digest, where
# buildx would otherwise wrap the manifest in a new index.
remote_tag="$registry/$image:$version_tag"
docker tag "$local_tag" "$remote_tag"
docker push "$remote_tag"
say "pushed $remote_tag"
if [ -n "$moving" ]; then
  docker buildx imagetools create --prefer-index=false \
    --tag "$registry/$image:$moving" "$remote_tag"
  say "tagged $registry/$image:$moving"
fi
