# Router-RS — Все ответы по опроснику (Single Source of Truth) — RU

Этот документ фиксирует принятые решения и ответы по блоку вопросов A–F. Он должен быть стабильным; дальнейшие изменения — через ADR.

## A. Перехват и форсирование маршрута (главное)

A1) Целевой механизм перехвата в v1  
Решение: **Windows Filtering Platform (WFP) + callout driver** — основной механизм interception/enforcement в v1.

A2) Допускается ли kernel-driver в v1  
Решение: **Да. Драйвер обязателен в v1.** Делаем “сразу нормально”, чтобы потом не переписывать архитектуру.

A3) “Маршрутизация по доменам”: откуда берём домен (must-have)  
Решение: **TLS SNI + HTTP Host + QUIC (SNI/ALPN где применимо)** — must-have в v1.  
Примечание: DNS допускается как вспомогательная корреляция/телеметрия, но **не** как единственный источник истины.

## Подпись и поставка драйвера

Стратегия подписи  
Решение:
- **Dev builds:** test-signed драйвер (для скорости разработки).
- **Public releases:** **Microsoft attestation signing** через Windows Hardware Dev Portal.

## B. Attribution (process ↔ flow ↔ domain)

B4) Как маппим поток на процесс в v1  
Решение: **WFP ALE metadata** — источник истины (PID + стабильные идентификаторы AppID/образ/путь).  
Ограничения:
- Учесть PID reuse (не полагаться только на PID).
- ETW/netstat — не основа, максимум diagnostics/вспомогательные инструменты.

B5) Если домен неизвестен (нет SNI/Host/QUIC, raw TCP и т.п.)  
Решение: **fallback по приложению → default.**
- Если домена нет, доменные правила не матчятся.
- Применяем правило по app (если есть), иначе default.
- Не делаем “require DNS correlation” как обязательный gate в v1.

## Семантика правил (как именно применяются правила)

Формы правил  
Решение: правила могут быть:
- `app + domain`
- `domain`
- `app`
- `default` (catch-all)

Итоговая модель применения (выбрана) — Модель №2  
Решение: **двухступенчатый матчинг: приоритет по специфичности, сверху вниз внутри каждого уровня.**

Уровни (в порядке применения):
1) `app + domain`
2) `domain`
3) `app`
4) `default`

Внутри уровня: **сверху вниз, первое совпадение побеждает.**

Конфликты и валидация  
Решение: **конфликты запрещены.**
- При применении конфига делаем строгую валидацию.
- При конфликте отклоняем конфиг и показываем понятную диагностику (что конфликтует и что исправить).
- Не “угадываем” разрешение конфликтов сверх фиксированной модели приоритетов.

## C. Модель egress

C6) Какие egress-ы в v1  
Решение: **SOCKS5-centric модель egress.**

Поддерживаемые типы/действия v1:
- `direct`
- `block`
- `socks5_endpoint` (локальный или удалённый endpoint)
- `process_provides_socks5` (управляемый процесс, который поднимает локальный SOCKS5)

HTTP proxy как отдельный тип egress  
Решение: **out of scope для v1** (если понадобится — через egress-процесс/адаптер, не усложняя ядро).

C7) VPN через sing-box: TUN или только SOCKS outbound  
Решение: **VPN egress = sing-box в TUN режиме** (как управляемый egress-процесс).  
Важно: см. предотвращение петель ниже.

## Предотвращение петель (hard requirement)

Требование  
Решение: **в v1 петли недопустимы** (hard requirement).

Подход (best practice)  
Решение: **egress процессы исключаются из interception/enforcement** (WFP bypass по AppID/образу/пути).  
Дополнительно:
- Исключаем loopback к локальным egress endpoints (127.0.0.1:PORT), чтобы не было self-intercept.

Граница компонентов: Nekobox не в цепочке  
Решение: **Nekobox/GUI “sandbox” не является компонентом прод-архитектуры.**  
Наш daemon управляет egress-агентами напрямую; сторонние UI не должны сидеть внутри цепочки роутинга.

## D. Dimensions правил (что реально в MVP v1)

D8) Dimensions в v1  
Решение: v1 поддерживает:
- `app`
- `domain`
- `dst_ip_cidr` (простое совпадение по destination IP/CIDR)

Точно откладываем до v2:
- `port/proto`
- GeoIP (`geo`)

Примечание: “по зоне домена” (например `*.ru`) — это **domain suffix matching**, а не GeoIP.

D9) Приоритет и действие `block`  
Решение: **`block` — обычное действие правила** (и/или default).  
Отдельного “pre-block слоя” не вводим: block подчиняется той же семантике уровней и порядку.

## E. IPC и UX

E10) GUI/TUI/CLI в v1  
Решение: **в v1 есть и GUI, и CLI.**
- GUI: **egui**.
- CLI: минимальный (для скриптов/автоматизации/диагностики).

E11) Live reload / профили / пресеты / import list  
Решение: v1 — **ручное применение** (кнопка Apply / `routerctl apply`) с максимально атомарным применением.  
Откладываем до v2:
- file-watch авто-reload
- профили/пресеты
- расширенные import/list механики (кроме минимальных include, если появятся)

## F. Сборка / распространение / привилегии

F12) Распространение  
Решение: **GitHub Releases + portable ZIP** для v1.  
MSI/winget — позже.

F13) Модель привилегий  
Решение: **service-based (вариант 3):**
- `routerd` работает как **Windows Service** (в админ-контексте).
- `routergui` и `routerctl` — **неадмин клиенты** через IPC.
- Elevation требуется только для install/update/remove драйвера/службы и других privileged операций.

Security: IPC защищаем ACL, чтобы не было несанкционированного управления политиками/egress.

F14) “Без Visual Studio” — цель?  
Решение: **нет, не цель.** VS/WDK допустимы для сборки драйвера.  
Пользователю VS не нужен для установки релизного ZIP.

---

## Итог: v1 scope (как согласовано)
- WFP callout driver (обязателен).
- Домены: TLS SNI + HTTP Host + QUIC (SNI/ALPN).
- Правила: `app+domain`, `domain`, `app`, `default` с tiered matching и top-to-bottom.
- Действия: direct / block / route-to-egress (SOCKS5-centric).
- Управляемые egress-процессы (VPN через sing-box TUN).
- Loop prevention: bypass egress процессов + исключение loopback к egress endpoints.
- GUI (egui) + минимальный CLI; daemon как Windows Service; клиенты неадмин через защищённый IPC.
- Дистрибуция: GitHub Releases ZIP; dev test-signed, public attestation-signed.
