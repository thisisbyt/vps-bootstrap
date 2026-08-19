# VPS Bootstrap

Проект для воспроизводимой подготовки VPS под будущую установку Xray/3x-ui, NaiveProxy, monitoring и сопутствующих сервисов.

Текущая версия: **v0.1.2**.

Primary target: **Ubuntu 24.04 LTS**.

Главная цель v0.1.x: доказать цепочку `runtime artifact -> bootstrap.sh -> Python CLI -> preflight -> state/resume -> verification` на свежей Ubuntu 24.04 до добавления VPN/proxy-компонентов.

## Что умеет v0.1

- запускается с единственной runtime-точки входа `bootstrap.sh`;
- проверяет Ubuntu 24.04, root/sudo, `apt-get`, состояние apt/dpkg;
- устанавливает только bootstrap dependencies;
- создаёт Python virtual environment внутри staged release: `/opt/vps-bootstrap/current/venv`;
- устанавливает управляемую копию проекта в `/opt/vps-bootstrap`;
- устанавливает команду `/usr/local/bin/vps-bootstrap`;
- показывает server info в SSH-терминале;
- выполняет preflight report с разделением fatal errors и warnings;
- создаёт runtime/config/log/state структуру;
- сохраняет state в `/var/lib/vps-bootstrap/state.json`;
- поддерживает `sudo vps-bootstrap resume`;
- перепроверяет `done` фазы перед skip;
- обеспечивает фактическую time synchronization в base/full setup, используя chrony как managed fallback, если systemd-timesyncd активен, но не синхронизирует часы;
- готовит Ansible foundation без применения OS changes через Ansible;
- собирается в production runtime artifact по explicit allowlist.

## Что v0.1 намеренно не делает

v0.1 не устанавливает и не настраивает:

- Xray;
- 3x-ui;
- PostgreSQL;
- NaiveProxy;
- Caddy;
- WARP;
- Telegram monitoring;
- SSH hardening;
- UFW rules;
- Fail2ban configuration;
- hostname;
- swap;
- sysctl networking.

Единственный новый managed component в v0.1.2 — `chrony`, и только как fallback для time synchronization.

## Production install на Ubuntu 24.04

Пока публичный release URL не определён, не используем команду вида `curl ... | bash`.

Production VPS не должен получать development repository целиком. На VPS передаётся только runtime artifact и `SHA256SUMS`.

После появления GitHub Release canonical flow:

```bash
VERSION="0.1.2"
REPO="<owner>/<repo>"

curl -fL -o "vps-bootstrap-v${VERSION}.tar.gz" \
  "https://github.com/${REPO}/releases/download/v${VERSION}/vps-bootstrap-v${VERSION}.tar.gz"
curl -fL -o SHA256SUMS \
  "https://github.com/${REPO}/releases/download/v${VERSION}/SHA256SUMS"

sha256sum -c SHA256SUMS
tar -xzf "vps-bootstrap-v${VERSION}.tar.gz"
cd "vps-bootstrap-v${VERSION}"
sudo bash bootstrap.sh full
```

Для public repository этот flow не требует GitHub credentials. Для private repository нужна отдельная authentication strategy; v0.1.2 не хранит GitHub token на VPS.

До публикации GitHub Release используйте development integration flow: собрать artifact локально, передать на VPS только `dist/vps-bootstrap-v0.1.2.tar.gz` и `dist/SHA256SUMS`, затем выполнить такую же checksum verification.

### Где выполнить

На VPS в Ubuntu SSH terminal от пользователя с sudo-доступом.

### Команды

```bash
cd /path/to/extracted/vps-bootstrap-v0.1.2
sudo bash bootstrap.sh full
```

Если executable bit у `bootstrap.sh` точно сохранён, допустим короткий вариант:

```bash
cd /path/to/extracted/vps-bootstrap-v0.1.2
sudo ./bootstrap.sh full
```

После bootstrap можно запускать CLI напрямую:

```bash
sudo vps-bootstrap
sudo vps-bootstrap preflight
sudo vps-bootstrap full
sudo vps-bootstrap resume
sudo vps-bootstrap state
```

### Проверка

```bash
sudo vps-bootstrap preflight
sudo vps-bootstrap full
sudo vps-bootstrap state
ls -ld /etc/vps-bootstrap /var/lib/vps-bootstrap /var/log/vps-bootstrap
sudo cat /var/lib/vps-bootstrap/state.json
```

### Ожидаемый результат

CLI должен показать информацию о сервере, понятный preflight report, затем завершить v0.1.2 setup. Warnings вроде отсутствующего swap или IPv6 не считаются fatal errors. В `full` фаза `time_sync` должна завершиться `DONE` только после фактической синхронизации часов.

### Важные примечания

- Команды требуют `sudo`.
- v0.1.2 не меняет SSH, firewall, DNS, hostname, swap, TLS и порты 80/443.
- v0.1.2 может установить и настроить `chrony`, если фактическая синхронизация времени отсутствует.
- Bootstrap выполняет `apt-get update` и устанавливает базовые пакеты, поэтому нужен доступ к Ubuntu repositories.
- End-to-end проверку нужно выполнять именно на Ubuntu 24.04 VPS; unit tests выполняются до сборки artifact локально или в CI.
- SHA256 защищает от повреждения или несоответствия artifact. Если сам release source скомпрометирован вместе с checksum, это не полноценная cryptographic publisher authentication; release signing остаётся future hardening item.

## Local release build

### Где выполнить

На development machine в корне repository.

### Команды

```bash
python3 -m unittest discover -s tests
python3 -m compileall app tests tools
bash -n bootstrap.sh
python3 tools/build_release.py
tar -tzf dist/vps-bootstrap-v0.1.2.tar.gz
```

### Проверка

```bash
cd dist
sha256sum -c SHA256SUMS
tar -tzf vps-bootstrap-v0.1.2.tar.gz | sed -n '1,80p'
```

### Ожидаемый результат

`dist/` содержит:

```text
vps-bootstrap-v0.1.2.tar.gz
SHA256SUMS
```

Archive содержит только runtime allowlist:

```text
vps-bootstrap-v0.1.2/bootstrap.sh
vps-bootstrap-v0.1.2/requirements.txt
vps-bootstrap-v0.1.2/versions.yml
vps-bootstrap-v0.1.2/app/
vps-bootstrap-v0.1.2/ansible/
vps-bootstrap-v0.1.2/templates/
```

`AGENTS.md`, `README.md`, `docs/`, `tests/`, `.git/`, `.github/`, `site/`, `tools/`, cache files and local secrets are absent.

## Runtime paths

```text
/etc/vps-bootstrap/config/
/etc/vps-bootstrap/secrets/
/var/lib/vps-bootstrap/state.json
/var/log/vps-bootstrap/vps-bootstrap.log
/opt/vps-bootstrap/current
/opt/vps-bootstrap/current/app/
/opt/vps-bootstrap/current/ansible/
/opt/vps-bootstrap/current/templates/
/opt/vps-bootstrap/current/versions.yml
/opt/vps-bootstrap/current/venv/
/opt/vps-bootstrap/releases/
/usr/local/bin/vps-bootstrap
```

TODO before heavier dependencies: define retention/cleanup policy for old releases under `/opt/vps-bootstrap/releases/`.

Secrets не хранятся в Git. Логи проходят через redaction-фильтр для токенов, паролей, private keys, auth headers и DB URLs с паролями.

Подробные инструкции для агента находятся в [AGENTS.md](AGENTS.md).
