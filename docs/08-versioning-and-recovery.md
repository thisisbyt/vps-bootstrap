# Версионирование, resume и recovery

## Версии

Критические компоненты должны иметь pinned/tested versions.

Пример структуры:

```yaml
xray:
  tested: "..."
  install_policy: pinned

three_x_ui:
  tested: "..."
  install_policy: pinned

caddy_naive:
  tested: "..."
  install_policy: pinned
```

Не использовать этот пример как реальные версии.

## Git tags

Релизы проекта:

```text
v0.1.0
v0.1.1
v0.1.2
v0.2.0
v0.3.0
```

Новый provisioning по умолчанию должен брать стабильный release/tag, а не произвольный latest commit из main.

## Runtime artifact

Production release состоит из:

```text
vps-bootstrap-vX.Y.Z.tar.gz
SHA256SUMS
```

Archive собирается только по `packaging/runtime-manifest.txt`; новый файл repository не попадает в runtime artifact без явного добавления в allowlist.

Git tag должен совпадать с `project.version` в `versions.yml`: `v0.1.2` соответствует `0.1.2`.

`main` branch не является production deployment source.

Production VPS должен скачать конкретный versioned artifact, проверить `sha256sum -c SHA256SUMS`, распаковать archive и только потом запустить `sudo bash bootstrap.sh`.

`SHA256SUMS` защищает от повреждения или несоответствия artifact, но не заменяет cryptographic publisher authentication, если release source и checksum скомпрометированы вместе.

Release assets для production tag immutable. Workflow не должен использовать `--clobber`; заменить artifact можно только новой project version и новым tag.

## v0.1.3 managed phase state

`swap` и `ssh_hardening` хранят только несекретное expected state, нужное для idempotency, verifier и repair.

Допустимые примеры:

```json
{
  "mode": "managed",
  "path": "/swapfile",
  "size_bytes": 2147483648
}
```

```json
{
  "mode": "managed",
  "ports": [25000],
  "activation_mode": "socket",
  "auth_values": {
    "PubkeyAuthentication": "yes",
    "PasswordAuthentication": "no"
  }
}
```

State не должен содержать private keys, passwords, SSH key material, tokens или auth headers.

Interrupted SSH migration является safety-sensitive состоянием. Resume не должен использовать stale transitional state, чтобы автоматически отключить старый SSH port.

v0.1.3 records SSH migration state before the first managed SSH write/restart:

```json
{
  "mode": "migration",
  "interrupted_migration": true,
  "old_ports": [22],
  "transition_ports": [22, 25000],
  "new_port": 25000,
  "activation_mode": "socket",
  "migration_stage": "planned"
}
```

Allowed migration stages are `planned`, `transition_applying`,
`transition_active`, `awaiting_second_session`, `finalizing` and `done`.
If resume sees `interrupted_migration=true`, default behavior is safety-first:
preserve the old port and require manual validation or rollback before any
finalization that could remove the old SSH listener.

## State machine

Каждая фаза имеет status:

```text
pending
running
done
failed
skipped
```

При повторном запуске:

- `done` сначала перепроверяется;
- если фактическое состояние совпадает — skip;
- если drift обнаружен — repair/re-run;
- `failed` можно повторить;
- destructive migration требует отдельной защиты.

## Resume

Пример:

```bash
sudo vps-bootstrap resume
```

Он должен:

1. загрузить state;
2. повторить preflight;
3. проверить уже выполненные фазы;
4. продолжить с первой незавершённой/сломавшейся;
5. не просить повторно секрет, если он безопасно сохранён локально и доступен;
6. никогда не вытаскивать секрет из Git.

## Backup before upgrade

Перед обновлением:

- 3x-ui;
- PostgreSQL schema/data;
- Xray config;
- Caddyfile;
- monitoring config;

создать timestamped backup.

Для PostgreSQL использовать логический dump (`pg_dump`).

## Rollback

Для каждого update module желательно иметь:

- previous version;
- previous config;
- previous DB backup;
- rollback action;
- verification after rollback.

## Drift

Проект должен уметь отличать:

- "уже установлено нами";
- "уже существовало до нас";
- "было изменено пользователем";
- "сломано".

Нельзя без предупреждения перетирать пользовательскую конфигурацию.
