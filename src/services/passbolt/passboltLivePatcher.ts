import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";

type SshAccessEntry = {
  ssh_host: string;
  ssh_port: number;
  ssh_user: string;
  identity_file: string;
};

type SshAccessMap = Record<string, SshAccessEntry>;

type PassboltSecrets = {
  vm: string;
  url: string;
  admin_email: string;
  admin_password: string;
  database_name: string;
  database_user: string;
  database_password: string;
  generated_at: string;
};

function readJson<T>(filePath: string): T {
  if (!fs.existsSync(filePath)) {
    throw new Error(`[Passbolt patch] Fichier introuvable: ${filePath}`);
  }

  return JSON.parse(fs.readFileSync(filePath, "utf-8")) as T;
}

function writeJsonAtomic(filePath: string, data: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });

  const tmpPath = `${filePath}.tmp`;

  fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), {
    encoding: "utf-8",
    mode: 0o600
  });

  fs.renameSync(tmpPath, filePath);
}

function randomSecret(length = 32): string {
  return crypto.randomBytes(length).toString("base64url");
}

function resolveIdentityFile(identityFile: string): string {
  if (identityFile.startsWith("~/")) {
    return path.join(process.env.USERPROFILE || process.env.HOME || "", identityFile.slice(2));
  }

  return identityFile;
}

function sshSecurityOptions(): string[] {
  const mode = process.env.SSH_TRUST_MODE ?? "lab";

  if (mode === "production") {
    return ["-o", "StrictHostKeyChecking=yes"];
  }

  return [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null"
  ];
}

function run(command: string, args: string[], cwd: string, label: string, allowFailure = false): string {
  console.log(`\n[Passbolt patch] ${label}`);
  console.log(`${command} ${args.join(" ")}`);

  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf-8",
    shell: false,
    maxBuffer: 1024 * 1024 * 50
  });

  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);

  if (result.error) throw result.error;

  if (!allowFailure && result.status !== 0) {
    throw new Error(`[Passbolt patch] Échec ${label} avec code ${result.status}`);
  }

  return result.stdout ?? "";
}

function sshArgs(entry: SshAccessEntry, remoteCommand: string): string[] {
  return [
    "-i",
    resolveIdentityFile(entry.identity_file),
    "-p",
    String(entry.ssh_port),
    ...sshSecurityOptions(),
    "-o",
    "LogLevel=ERROR",
    `${entry.ssh_user}@${entry.ssh_host}`,
    remoteCommand
  ];
}

function ensureGitignore(outputRoot: string): void {
  const gitignorePath = path.join(process.cwd(), ".gitignore");
  const linesToAdd = [
    "outputs/passbolt-secrets.local.json",
    "outputs/passbolt.env",
    "outputs/secrets.json",
    "outputs/generated-lab/secrets/"
  ];

  const current = fs.existsSync(gitignorePath)
    ? fs.readFileSync(gitignorePath, "utf-8")
    : "";

  const missing = linesToAdd.filter((line) => !current.includes(line));

  if (missing.length === 0) return;

  fs.appendFileSync(
    gitignorePath,
    `${current.endsWith("\n") || current.length === 0 ? "" : "\n"}${missing.join("\n")}\n`,
    "utf-8"
  );

  console.log(`[Passbolt patch] .gitignore mis à jour pour exclure les secrets.`);
}

function buildBootstrapCommand(secrets: PassboltSecrets): string {
  const adminPassword = secrets.admin_password.replace(/'/g, "'\"'\"'");
  const dbPassword = secrets.database_password.replace(/'/g, "'\"'\"'");

  return [
    "set -e",
    "export DEBIAN_FRONTEND=noninteractive",

    "sudo apt-get update",

    [
      "sudo apt-get install -y",
      "curl",
      "wget",
      "gnupg",
      "ca-certificates",
      "lsb-release",
      "openssl",
      "nginx",
      "mariadb-server",
      "php-fpm",
      "php-cli",
      "php-mysql",
      "php-gnupg",
      "php-intl",
      "php-mbstring",
      "php-xml",
      "php-curl",
      "php-gd",
      "php-zip",
      "php-bcmath",
      "php-common",
      "unzip",
      "git",
      "acl"
    ].join(" "),

    "sudo systemctl enable --now nginx || true",
    "sudo systemctl enable --now mariadb || true",
    "sudo systemctl enable --now php*-fpm || true",

    `sudo mysql -e "CREATE DATABASE IF NOT EXISTS ${secrets.database_name} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"`,
    `sudo mysql -e "CREATE USER IF NOT EXISTS '${secrets.database_user}'@'localhost' IDENTIFIED BY '${dbPassword}';"`,
    `sudo mysql -e "GRANT ALL PRIVILEGES ON ${secrets.database_name}.* TO '${secrets.database_user}'@'localhost'; FLUSH PRIVILEGES;"`,

    "sudo mkdir -p /opt/passbolt-lab",
    `sudo /bin/sh -c 'cat > /opt/passbolt-lab/passbolt-lab.env <<EOF\nPASSBOLT_URL=${secrets.url}\nPASSBOLT_ADMIN_EMAIL=${secrets.admin_email}\nPASSBOLT_ADMIN_PASSWORD=${adminPassword}\nPASSBOLT_DB_NAME=${secrets.database_name}\nPASSBOLT_DB_USER=${secrets.database_user}\nPASSBOLT_DB_PASSWORD=${dbPassword}\nEOF'`,
    "sudo chmod 600 /opt/passbolt-lab/passbolt-lab.env",

    "sudo openssl req -x509 -nodes -days 365 -newkey rsa:3072 -keyout /etc/ssl/private/passbolt-lab.key -out /etc/ssl/certs/passbolt-lab.crt -subj '/CN=passbolt.lab.local' >/dev/null 2>&1 || true",
    "sudo chmod 600 /etc/ssl/private/passbolt-lab.key || true",

    "sudo /bin/sh -c 'cat > /etc/nginx/sites-available/passbolt-lab <<EOF\nserver {\n    listen 443 ssl;\n    server_name passbolt.lab.local passbolt-1;\n\n    ssl_certificate /etc/ssl/certs/passbolt-lab.crt;\n    ssl_certificate_key /etc/ssl/private/passbolt-lab.key;\n\n    add_header X-Frame-Options SAMEORIGIN always;\n    add_header X-Content-Type-Options nosniff always;\n    add_header Referrer-Policy no-referrer always;\n\n    location / {\n        return 200 \"Passbolt lab bootstrap OK. Installer Passbolt CE package/source next.\\\\n\";\n        add_header Content-Type text/plain;\n    }\n}\nEOF'",

    "sudo ln -sf /etc/nginx/sites-available/passbolt-lab /etc/nginx/sites-enabled/passbolt-lab",
    "sudo rm -f /etc/nginx/sites-enabled/default",
    "sudo nginx -t",
    "sudo systemctl reload nginx",

    "sudo ufw --force reset >/dev/null 2>&1 || true",
    "sudo ufw default deny incoming >/dev/null 2>&1 || true",
    "sudo ufw default allow outgoing >/dev/null 2>&1 || true",
    "sudo ufw allow 22/tcp >/dev/null 2>&1 || true",
    "sudo ufw allow 443/tcp >/dev/null 2>&1 || true",
    "sudo ufw --force enable >/dev/null 2>&1 || true",

    "sudo systemctl status nginx --no-pager || true",
    "sudo systemctl status mariadb --no-pager || true",
    "curl -k -I https://127.0.0.1/ || true"
  ].join("; ");
}

export function patchLivePassbolt(outputRoot: string): void {
  const generatedLabDir = path.join(outputRoot, "generated-lab");
  const sshAccessPath = path.join(outputRoot, "ssh-access.local.json");

  const sshAccess = readJson<SshAccessMap>(sshAccessPath);
  const passboltSsh = sshAccess["passbolt-1"];

  if (!passboltSsh) {
    throw new Error("[Passbolt patch] passbolt-1 introuvable dans ssh-access.local.json");
  }

  ensureGitignore(outputRoot);

  const secretsPath = path.join(outputRoot, "passbolt-secrets.local.json");

  const secrets: PassboltSecrets = fs.existsSync(secretsPath)
    ? readJson<PassboltSecrets>(secretsPath)
    : {
        vm: "passbolt-1",
        url: "https://passbolt.lab.local",
        admin_email: "admin@lab.local",
        admin_password: randomSecret(24),
        database_name: "passbolt",
        database_user: "passbolt",
        database_password: randomSecret(24),
        generated_at: new Date().toISOString()
      };

  writeJsonAtomic(secretsPath, secrets);

  const sshCommand = process.platform === "win32" ? "ssh.exe" : "ssh";

  run(
    sshCommand,
    sshArgs(passboltSsh, buildBootstrapCommand(secrets)),
    generatedLabDir,
    "Bootstrap sécurisé Passbolt"
  );

  console.log(`[Passbolt patch] Secrets locaux générés : ${secretsPath}`);
  console.log(`[Passbolt patch] URL lab : https://127.0.0.1:9440 ou ${secrets.url}`);
}