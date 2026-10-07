#!/usr/bin/env bash
# Spin up RustFS in docker, create one object-locked bucket and one public plain bucket,
# run eimer against it, tear down. MinIO images are no longer published, RustFS is the
# migration target, and the AWS CLI keeps the setup vendor neutral.
set -euo pipefail
cd "$(dirname "$0")/.."

NAME=eimer-smoke
PORT=${PORT:-19000}
export AWS_ACCESS_KEY_ID=eimeradmin AWS_SECRET_ACCESS_KEY=eimersecret AWS_REGION=us-east-1
ENDPOINT="http://127.0.0.1:$PORT"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

docker run -d --name "$NAME" -p "$PORT:9000" \
  -e RUSTFS_ACCESS_KEY="$AWS_ACCESS_KEY_ID" -e RUSTFS_SECRET_KEY="$AWS_SECRET_ACCESS_KEY" \
  rustfs/rustfs:latest >/dev/null

for _ in $(seq 1 30); do
  curl -s -o /dev/null "$ENDPOINT/" && break
  sleep 1
done

aws() {
  docker run --rm --network host \
    -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_REGION \
    amazon/aws-cli:latest --endpoint-url "$ENDPOINT" "$@"
}

aws s3api create-bucket --bucket worm --object-lock-enabled-for-bucket >/dev/null
aws s3api put-object-lock-configuration --bucket worm --object-lock-configuration \
  '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":30}}}'
aws s3api put-object --bucket worm --key held.txt --body /etc/hostname >/dev/null

aws s3api create-bucket --bucket plain >/dev/null
aws s3api put-object --bucket plain --key x.txt --body /etc/hostname >/dev/null
aws s3api put-bucket-policy --bucket plain --policy \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::plain/*"}]}'

OUT=$(mktemp -d)
echo "== text + evidence file"
./bin/eimer audit --endpoint "$ENDPOINT" --out "$OUT/before.json" || echo "(exit $?)"
cat "$OUT/before.json.sha256"

echo "== change something, audit again, diff"
aws s3api delete-bucket-policy --bucket plain
aws s3api put-object --bucket plain --key y.txt --body /etc/hostname >/dev/null
./bin/eimer audit --endpoint "$ENDPOINT" --json --out "$OUT/after.json" >/dev/null || true
./bin/eimer diff "$OUT/before.json" "$OUT/after.json" || echo "(exit $?)"
rm -rf "$OUT"
