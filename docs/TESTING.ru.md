# Проверка OpenShield (русская версия)

> Английский оригинал: [TESTING.md](TESTING.md). При расхождениях верен оригинал.

## Автоматические тесты

Их запускает CI на каждом push, можно запустить и у себя. Права администратора
и WinDivert для них не нужны.

```powershell
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Ручной чек-лист: этап 1 (DNS-фильтрация)

Здесь мы по-настоящему запускаем драйвер WinDivert и перехватываем DNS-запросы
компьютера. Поэтому эти шаги никогда не выполняются скриптами или CI —
только вручную.

Понадобятся **два окна PowerShell**:

| Окно | Как открыть | Зачем |
|---|---|---|
| **Окно 1** (администратор) | `Win + X` → «Терминал (администратор)» → подтвердить UAC | Подготовка и запуск OpenShield |
| **Окно 2** (обычное) | `Win + X` → «Терминал» | Проверочные DNS-запросы |

В **обоих** окнах сначала перейдите в папку проекта:

```powershell
cd C:\dev\openshield
```

---

### Подготовка (один раз, в окне 1)

**Шаг А. Исключение для Defender.** Defender считает архив WinDivert
нежелательной программой (это ложное срабатывание, см. ADR-005). Разрешаем
только одну папку, куда он будет скачан:

```powershell
Add-MpPreference -ExclusionPath 'C:\dev\openshield\third_party'
```

Ничего не выведет — это нормально. Отменить потом можно командой
`Remove-MpPreference -ExclusionPath 'C:\dev\openshield\third_party'`.

**Шаг Б. Скачать WinDivert и собрать программу:**

```powershell
powershell -ExecutionPolicy Bypass -File scripts\dev-setup.ps1
```

Ожидается в конце: `SHA-256 verified`, `Driver signature: Valid` и
`WinDivert 2.2.2 is ready in ...`.

```powershell
cargo build --release
```

Ожидается: `Finished release profile`.

```powershell
.\target\release\openshield-cli.exe --data-dir dev-data lists update
```

Ожидается: строки списков с `updated`, `not modified` или `up to date`.

**Шаг В. Запомнить путь к WinDivert** (переменная живёт только в этом окне;
если окно закроете — выполните снова):

```powershell
$wd = 'third_party\windivert\WinDivert-2.2.2-A\x64'
```

---

### Проверки

#### 1. Запуск (окно 1)

```powershell
.\target\release\openshield-service.exe --console --data-dir dev-data --windivert-dir $wd --stats-interval 15
```

Ожидается: строки о загрузке списков (`AdGuard DNS filter: ... rules`),
`matcher ready: ... domains`, `WinDivert driver 2.x` и в конце
**`DNS filtering active. Press Ctrl+C to stop.`**

Если Windows использует DNS-over-HTTPS, появится жёлтое предупреждение
`Windows DNS over HTTPS seems to be enabled` — это не ошибка, просто запомните
его для отчёта.

Окно 1 **не закрывайте** — программа работает, пока оно открыто. Дальше
работаем в окне 2.

#### 2. Блокировка рекламного домена (окно 2)

```powershell
nslookup doubleclick.net
```

Ожидается в ответе: **`Address: 0.0.0.0`** (вместо настоящего адреса).

#### 3. Блокировка для IPv6 (окно 2)

```powershell
Resolve-DnsName ad.doubleclick.net -Type AAAA
```

Ожидается: в колонке `IPAddress` значение **`::`**.

#### 4. Отключение DoH в Firefox (окно 2)

```powershell
Resolve-DnsName use-application-dns.net
```

Ожидается: красная ошибка **`DNS name does not exist`** (это и есть NXDOMAIN —
так и должно быть).

#### 5. DNS через TCP (окно 2)

```powershell
nslookup -vc doubleclick.net
```

Ожидается: **любая ошибка** (например, `timed out` или сброс соединения) и
**нет** настоящего адреса.

Если всё равно пришли настоящие адреса: остановите программу в окне 1
(**Ctrl+C**), запустите её с флагом `-v` (добавьте ` -v` в конец команды из
пункта 1), повторите `nslookup -vc doubleclick.net`, снова нажмите Ctrl+C и
пришлите строки со словами `reply injection failed` (если есть) и
`packet loop finished: ...`.

#### 6. Обычные сайты работают (окно 2 и браузер)

```powershell
Resolve-DnsName github.com
```

Ожидается: настоящие IP-адреса. Откройте в браузере пару обычных сайтов —
они должны работать как всегда.

#### 7. Статистика (окно 1)

Подождите 15 секунд и посмотрите в окно 1.

Ожидается строка вида `stats: 42 queries, 7 blocked (16.7%)` и под ней
`top blocked: ...` и `top queried: ...`.

#### 8. Интернет не ломается, если программу «убить» (окно 2)

```powershell
taskkill /F /IM openshield-service.exe
ipconfig /flushdns
nslookup doubleclick.net
```

Ожидается: в окне 1 программа завершилась; `nslookup` теперь показывает
**настоящий адрес** (не `0.0.0.0`) — фильтр исчез, а интернет работает.
Браузер тоже работает.

#### 9. Нормальная остановка (окно 1)

Запустите программу снова командой из пункта 1, дождитесь
`DNS filtering active` и нажмите **Ctrl+C**.

Ожидается: `stopping`, `packet loop finished: ...`, итоговая статистика,
программа завершилась. Сайты в браузере продолжают открываться.

#### 10. Тест watchdog — искусственное зависание (окно 1 и окно 2)

Проверяем, что если программа **зависнет** (а не упадёт), интернет всё равно
продолжит работать.

В **окне 1** соберите специальную тестовую версию и запустите её — она
нарочно «зависнет» на 5-м DNS-запросе:

```powershell
cargo build --release -p openshield-service --features fault-injection
.\target\release\openshield-service.exe --console --data-dir dev-data --windivert-dir $wd --debug-stall-after 5
```

Когда появится `DNS filtering active`, в **окне 2** сделайте несколько
запросов:

```powershell
1..8 | % { Resolve-DnsName "test$_.example.com" -ErrorAction SilentlyContinue }
```

Ожидается в **окне 1**:

1. `fault injection: hanging on packet 5` — программа «зависла»;
2. примерно через 3 секунды —
   `watchdog: packet loop stuck for ...s; capture released ...` — watchdog
   отпустил перехват;
3. программа завершилась сама.

Сразу после этого в **окне 1** выполните:

```powershell
$LASTEXITCODE
```

Ожидается: **`2`**.

В окне 2 запросы в это время продолжали работать (один «застрявший» запрос
Windows просто повторила). Проверьте: `Resolve-DnsName github.com` — настоящий
адрес.

После теста **пересоберите обычную версию** (окно 1):

```powershell
cargo build --release
```

#### 11. Откат всех изменений (окно 1)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\cleanup.ps1
```

Ожидается в конце: **`Cleanup finished.`** без предупреждений.

---

### Что прислать в ответ

Для каждого пункта 1–11: **прошёл / не прошёл**. Если что-то не прошло —
приложите:

- текст из окна 1 (особенно строки `WARN` и `ERROR` и что вокруг них);
- команду, которую вводили, и что она вывела;
- для пункта 10 — значение `$LASTEXITCODE`.

Если `WinDivertOpen` выдаст ошибку, в ней будет код и подсказка. Например:
**5** — окно запущено не от администратора; **577** — Windows отклонила подпись
драйвера; **1275** — драйвер заблокирован политикой или антивирусом.
