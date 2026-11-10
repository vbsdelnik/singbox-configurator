# 3x-ui → sing-box

Конвертер на Python 3.9+ без сторонних библиотек. Принимает отдельные VLESS URI, файлы со списком ссылок и URL подписок 3x-ui. Подписка может содержать обычный текст или список в Base64 (обычный и URL-safe алфавиты, с padding или без него). На выходе — обычный JSON для импорта в sing-box.

## Запуск

Команды выполняются из каталога с `converter.py`. Пример использует вымышленные UUID и адреса из диапазона для документации.

```sh
python3 converter.py --input examples/vless.txt -o config.json
```

Для одной или нескольких ссылок сохраните их по одной на строку в локальном файле `private-vless.txt`. Сохранённый ответ сервера подписки можно передать тем же способом.

```sh
python3 converter.py --input private-vless.txt -o config.json
python3 converter.py --input - -o config.json < saved-subscription.txt
```

Для загрузки подписки сохраните её полный URL одной строкой в локальном файле `private-subscription-url.txt`.

```sh
python3 converter.py --subscription-url-file private-subscription-url.txt -o config.json
python3 converter.py --input private-vless.txt --subscription-url-file private-subscription-url.txt -o config.json
```

Есть также повторяемые флаги `--vless URI` и `--subscription URL`. Для реальных ссылок используйте файлы или stdin, чтобы URI и токен подписки не попали в историю оболочки или список процессов. Stdin можно задействовать для одного источника. URL подписки должен использовать HTTPS. Для подписки по HTTP в доверенной сети укажите `--allow-http`. Перенаправления допускаются только на HTTPS.

Смешанные подписки поддерживаются. Другие протоколы пропускаются, а ошибка в VLESS URI прерывает генерацию и сообщает номер источника и записи. Точные дубликаты по настройкам подключения объединяются, совпадающие названия получают числовой суффикс. Порядок обработки — флаги `--vless`, локальные списки, подписки из `--subscription`, затем подписки из `--subscription-url-file`.

## Что берётся из шаблона

По умолчанию используется `template.jsonc`, подготовленный из вложенного `er2-bublik.json`. Старый VLESS-узел удалён, а его ссылки в группах заменены на `@VLESS@`. При генерации конвертер разворачивает эту метку в список новых узлов. Сохраняются настройки DNS, TUN и порядок правил маршрутизации, включая выход через `direct-out` для `ru-domains`, локальных адресов и остальных исключений исходного файла.

`auto-proxy-out` проверяет новые узлы с исходными параметрами URLTest. `proxy-out`, `vpn ①` и `vpn ②` получают новые узлы и сохраняют варианты по умолчанию. Группа `ru VPN 🇷🇺` сохраняет `direct-out` как единственный вариант.

Исходный файл редактора можно передать напрямую.

```sh
python3 converter.py --template er2-bublik.json --input private-vless.txt -o config.json
```

В `outbounds` должна быть одна пара комментариев `@ParserSTART` и `@ParserEND`, охватывающая целые элементы массива. VLESS-узлы внутри блока заменяются, ссылки на их теги внутри групп разворачиваются в список новых узлов. Если старый VLESS-тег был значением `default`, используется первый новый узел. В собственном шаблоне ссылайтесь из DNS и маршрутов на стабильные теги групп. Маркеры `@ParserSTART_E` и `@ParserEND_E` относятся к массиву `endpoints`, его содержимое сохраняется. JSONC-комментарии и завершающие запятые удаляются при формировании результата.

## Поддерживаемые параметры VLESS

- TCP (`tcp` и `raw`), WebSocket, gRPC в обычном режиме, HTTP/2 (`http` и `h2`) и HTTPUpgrade. Поддерживаются адреса IPv4, IPv6 в квадратных скобках и доменные имена.
- `security=none`, `tls` и `reality`. Для REALITY переносятся `sni`, `fp`, `pbk`, `sid` и `flow=xtls-rprx-vision`, если он указан. По умолчанию REALITY использует отпечаток `chrome`. Пустой `sid` допустим, если он настроен на сервере.
- `spx` относится к поведению клиента Xray и опускается. Параметры без поддерживаемого соответствия, такие как XHTTP, TCP с HTTP-заголовком, VLESS-шифрование, REALITY `pqv` и расширения TLS, перечисленные в коде, приводят к явной ошибке. Отключение проверки TLS через URI также приводит к ошибке. Остальные неизвестные параметры URI игнорируются.

## Секреты и проверка

Выходной файл содержит UUID и параметры подключения. На macOS/Linux он создаётся с правами `0600`. У поставляемого шаблона поле секрета Clash API пустое, поэтому конвертер генерирует новый случайный секрет при каждом запуске. Непустой секрет пользовательского шаблона сохраняется. Сообщения CLI содержат только статус и позицию записи. Вывод внешней проверки скрыт, поскольку он может включать значения из конфига.

```sh
python3 converter.py --input examples/vless.txt --check sing-box -o config.json
python3 -B -m unittest -v
SING_BOX_TEST_BINARY="$(command -v sing-box)" python3 -B -m unittest -v
```

С `--check` конвертер заменяет выходной файл только после успешного `sing-box check`. Официальный sing-box 1.14.4 на macOS ARM64 успешно загрузил конфиг из примера. Подключение и разделение трафика проверяются отдельно на реальном узле и целевом устройстве.

[Формат VLESS и TLS в sing-box](https://sing-box.sagernet.org/configuration/outbound/vless/) · [REALITY и uTLS](https://sing-box.sagernet.org/configuration/shared/tls/) · [Подписки 3x-ui](https://github.com/MHSanaei/3x-ui/blob/main/docs/content/docs/en/reference/api/subscription-server.mdx)

## Публикация на GitHub

Создайте пустой репозиторий на GitHub и выполните в локальном репозитории:

```sh
git remote add origin https://github.com/USERNAME/singbox-configurator.git
git push -u origin main
```

Храните реальные ссылки и локальные конфиги в файлах с префиксом `private-` или именами `config.json` и `config.local*.json`. Git исключает эти имена, а также исходный экспорт `er2-bublik.json`.
