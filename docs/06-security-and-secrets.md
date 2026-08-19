# Безопасность и секреты

## Репозиторий

Репозиторий должен быть безопасен даже если станет публичным.

Поэтому архитектура не должна полагаться на приватность GitHub как на механизм защиты секретов.

## `.gitignore`

Минимально игнорировать:

```gitignore
.env
.env.*
secrets.*
*.key
*.pem
*.p12
*.pfx
*.sqlite
*.db
backups/
runtime/
state/
```

Исключения для test fixtures должны быть явно документированы.

## Runtime secrets

Предпочтительное размещение:

```text
/etc/vps-bootstrap/secrets.env
```

Права:

```bash
sudo chown root:root /etc/vps-bootstrap/secrets.env
sudo chmod 600 /etc/vps-bootstrap/secrets.env
```

## Logs

Никогда не логировать:

- passwords;
- tokens;
- private keys;
- auth headers;
- DB connection strings с паролем.

Перед логированием команды маскировать секретные аргументы.

## SSH

Предпочтительно:

- keys вместо password authentication;
- root login ограничить/отключить после создания sudo user, если пользователь выбрал такой режим;
- не менять всё одновременно без проверки второго доступа;
- хранить emergency rollback instructions.

## PostgreSQL

По умолчанию:

- listen locally;
- не открывать 5432 в UFW;
- отдельный DB user;
- отдельная database;
- least privilege;
- strong generated password;
- backup через `pg_dump`;
- restore test для важных production-конфигураций.

## Admin panels

3x-ui не должна без необходимости слушать весь Internet.

Предусмотреть варианты:

- localhost + SSH tunnel;
- private/VPN address;
- reverse proxy;
- отдельный management port с firewall restriction.

Конкретный вариант выбирается пользователем.

## TLS private keys

TLS private keys не копируются в Git.

Backup таких данных требует отдельной защищённой стратегии.

## Telegram

Bot Token считается секретом.

Не включать его:

- в URL, который попадает в shell history, если можно избежать;
- в публичные логи;
- в Git;
- в вывод install summary.
