#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${SOCI_IMAGE:-soci-sgx-hw:2.26}"
cp_image="${SOCI_CP_IMAGE:-soci-sgx-cp:2.26}"
csp_image="${SOCI_CSP_IMAGE:-soci-sgx-csp:2.26}"
output="${1:-$project_dir/dist/soci-sgx-hw-2.26.tar.gz}"
mkdir -p "$(dirname "$output")"

docker build -f "$project_dir/docker/Dockerfile.hw" -t "$image" "$project_dir"
docker build -f "$project_dir/docker/Dockerfile.hw" --target cp-image -t "$cp_image" "$project_dir"
docker build -f "$project_dir/docker/Dockerfile.hw" --target csp-image -t "$csp_image" "$project_dir"
docker image inspect "$image" --format '{{.Id}}' > "${output%.tar.gz}.image-id.txt"
docker save "$image" "$cp_image" "$csp_image" | gzip -1 > "$output"
(
  cd "$(dirname "$output")"
  sha256sum "$(basename "$output")" > "$(basename "$output").sha256"
)
cp "$project_dir/docker/compose.hw.deploy.yaml" "$(dirname "$output")/"
cp "$project_dir/docker/compose.hw.cp-csp.deploy.yaml" "$(dirname "$output")/"

echo "Image: $image"
echo "Role images: $cp_image, $csp_image"
echo "Archive: $output"
echo "Checksum: $output.sha256"
