# Security review: tedee_ble (ACP-123)

- Repozytorium: fork `sagan-dev/tedee_ble` z `meltingice1337/tedee_ble` (MIT)
- Przegląd na commicie upstream `ee6677f5be4f696594276cb8ee3638bcd283e82d` (tag `v0.3.1`, 2026-10-16). Numery linii odnoszą się do tego commita, chyba że napisano inaczej.
- Data: 2026-11-15
- Metoda: tylko analiza statyczna i testy offline na ai-ops. Integracji nie instalowano w Home Assistant, nie było połączenia z zamkiem (BLE) ani z Tedee API na prawdziwym koncie, nie użyto żadnych tokenów.
- Narzędzia: bandit 1.9.4, pip-audit 2.10.1, semgrep 1.185.0 (`p/python`, `p/javascript`, `p/secrets`, `p/github-actions`), ruff 0.17.5 (`S`, `B`, `ASYNC`) oraz własne testy PoC w pytest, uruchomione w namespace bez sieci (`unshare -rn`) z zaślepką zamiast `bleak`.

## Werdykt

**Instalować po poprawkach.**

Rdzeń kryptografii jest poprawny. Używa biblioteki `cryptography` (ECDH P-256, ECDSA, AES-GCM), nie ma własnych prymitywów, a podpis zamka jest weryfikowany kluczem publicznym z Tedee Cloud, więc nie da się podszyć pod zamek w handshake'u. W kodzie nie ma eval/exec/subprocess/pickle/dynamicznych importów ani pobierania kodu w runtime. Łączy się tylko z `https://api.tedee.com` z domyślną weryfikacją TLS. Logi nie zawierają kluczy ani PAK, a integracja nie ma pliku diagnostics.

Przed instalacją trzeba jednak:

1. Naprawić **H1**: po zestawieniu sesji PTLS integracja przyjmuje nieszyfrowane ramki i traktuje je jak prawdziwy stan zamka. Poprawka jest mała, ale wymaga testu na prawdziwym zamku, więc nie ma jej w tym PR (szczegóły niżej). Druga możliwość: Michał świadomie akceptuje ryzyko i żadna automatyzacja bezpieczeństwa (alarm, powiadomienia „drzwi zamknięte”) nie opiera się na stanie tego zamka.
2. Scalić ten PR. Zawiera poprawkę karty (M4), sprzątanie po nieudanym setupie (M5) i przypięcie akcji CI (L1).
3. Spełnić warunki operacyjne z sekcji „Warunki instalacji”: zakresy PAK, szyfrowane backupy, instalacja z forka, a nie z ZIP-a upstream.

Krytycznych findings brak.

## Findings

| ID | Waga | Tytuł | Status |
|----|------|-------|--------|
| H1 | Wysokie | Nieszyfrowane ramki BLE są akceptowane po zestawieniu sesji PTLS (fałszywy stan zamka / wynik komendy) | otwarte, rekomendacja |
| M1 | Średnie | Config entry HA zawiera w jawnej postaci PAK (z `Mobile.ReadWrite`), klucz prywatny i certyfikat, czyli „klucz do drzwi” | otwarte, operacyjne |
| M2 | Średnie | Usunięcie integracji nie wyrejestrowuje „mobile” w Tedee | otwarte, operacyjne |
| M3 | Średnie | Wydanie HACS to ZIP budowany lokalnie przez autora (`zip_release`), którego nie da się odtworzyć z taga | otwarte, operacyjne |
| M4 | Średnie | Karta Lovelace pokazywała `last_action` zamiast stanu encji: mogła pokazać „Locked”, gdy zamek był otwarty lub zablokowany | **naprawione** w PR |
| M5 | Średnie | Po nieudanym setupie zostaje osierocony koordynator z otwartym łączem BLE, który sam się reconnectuje | **naprawione** w PR |
| L1 | Niskie | Akcje GitHub nieprzypięte do SHA; hassfest bez `permissions` | **naprawione** w PR |
| L2 | Niskie | Zależności: dolne granice wersji, `cryptography>=41.0` w `requirements.txt` (CLI) z CVE | **częściowo naprawione** (CLI) |
| L3 | Niskie | Zapisany MAC zamka nadpisywany na podstawie nieuwierzytelnionej reklamy BLE, przed handshake'iem | otwarte, rekomendacja |
| L4 | Niskie | 16-bitowy licznik nonce AES-GCM, który przy >65535 wiadomościach w sesji się zawija | otwarte, teoretyczne |
| L5 | Niskie | Nieograniczone kolejki `asyncio.Queue` na dane od peera BLE | otwarte |
| L6 | Niskie | Logi debug zawierają surowe ramki i nazwy użytkowników; błędy API zawierają całą odpowiedź | otwarte |
| L7 | Niskie | Nazwy użytkowników z logu aktywności Tedee trafiają do config entry i atrybutu `last_user` (recorder) | otwarte, info |
| L8 | Niskie | Brak `code_format`: każdy użytkownik HA i każde wystawione API (Assist/Google/HomeKit) może wykonać unlock/open | otwarte, konfiguracja HA |
| L9 | Info | `cli.py` zapisuje `config.json` z PAK bez `chmod 600` | otwarte (tylko CLI) |
| L10 | Info | Integracja sama rejestruje zasób Lovelace (`/tedee-ble/tedee-lock-card.js`) we wszystkich dashboardach | info |

---

### H1. Nieszyfrowane ramki akceptowane po zestawieniu sesji PTLS (Wysokie)

**Co sprawdzono:** obsługę nagłówka ramki w `TedeeLock.parse_notification` i w `PTLSSession._decrypt_inner`.

**Wynik:**
- `custom_components/tedee_ble/tedee_lib/lock_commands.py:362-388`: ramka z nagłówkiem `0x01` jest deszyfrowana. Ramka z nagłówkiem `0x00` (`DATA_NOT_ENCRYPTED`) jest przyjmowana bez uwierzytelnienia. Ramka z **dowolnym innym** nagłówkiem nie jest ani odrzucana, ani deszyfrowana, tylko parsowana tak, jakby jej pierwszy bajt był ID notyfikacji. Ramka `BA 06 ...` (nagłówek `0x0A`) jest więc interpretowana jako `LOCK_STATUS_CHANGE = LOCKED`.
- `custom_components/tedee_ble/tedee_lib/ptls.py:457-458`: `_decrypt_inner` dla nagłówka `0x00` zwraca `data[1:]` jako „odszyfrowany” plaintext. Korzysta z tego `_send_command` (`lock_commands.py:207-225`), więc odpowiedź na `GET_STATE`/`LOCK`/`UNLOCK` też da się podrobić, np. fałszywym `SUCCESS` albo fałszywym stanem.
- Skutek w HA: `coordinator.py:965-995` ustawia `lock_state` z notyfikacji, wywołuje zdarzenie `tedee_ble_lock_action` (logbook i automatyzacje) i aktualizuje encję.

**Dowód (test offline, bez sieci):**
```
test_plaintext_header_lock_state_is_accepted   PASSED  (0x00 BA 06 ... -> lock_state LOCKED, bez deszyfrowania)
test_headerless_frame_is_accepted              PASSED  (BA 06 ...      -> lock_state LOCKED)
test_ptls_decrypt_returns_plaintext_for_header_0 PASSED
```

**Warunki ataku:** aktywny MITM/relay BLE w zasięgu radiowym zamka albo adaptera/proxy HA, np. narzędziami klasy GATTacker/btlejuice. Atakujący przekazuje zaszyfrowany ruch PTLS bez zmian i wstrzykuje własne nieszyfrowane notyfikacje. Tą drogą **nie da się otworzyć drzwi**, bo komendy wymagają sesji PTLS. Można natomiast sprawić, że HA pokaże „zamknięte” przy otwartym zamku, sfałszować wpis w logbooku albo potwierdzić komendę, która nie doszła.

**Rekomendowana poprawka** (mała, ale wymaga testu na prawdziwym zamku, bo nie wiem, czy firmware wysyła cokolwiek jawnym tekstem po handshake'u):
1. W `parse_notification` odrzucać każdą ramkę z nagłówkiem innym niż `0x00`/`0x01`.
2. Gdy `session.is_established`, odrzucać `0x00` przynajmniej dla `LOCK_STATUS_CHANGE`, `SIGNED_DATETIME` i stanów baterii, i logować to jako warning. Najprościej odrzucać wszystkie jawne ramki i obserwować logi przez kilka dni.
3. W `PTLSSession._decrypt_inner` po zestawieniu sesji nie zwracać plaintextu dla `0x00`, tylko rzucać `PTLSError`. `_send_command` już pomija takie ramki i czeka na właściwą odpowiedź.

---

### M1. Config entry = klucz do drzwi (Średnie)

**Co sprawdzono:** co i gdzie integracja zapisuje.

**Wynik:** `config_flow.py:394-413` zapisuje w `entry.data` w jawnej postaci: `api_key` (Tedee Personal Access Key), `private_key_pem` (klucz ECDSA P-256 „telefonu” bez hasła, `crypto.py:17-22`), `certificate`, `mobile_id` i `signed_time`. HA przechowuje to w `/config/.storage/core.config_entries` i dołącza do backupów. To standardowy mechanizm HA, inne integracje działają tak samo. Kto ma odczyt `.storage` albo niezaszyfrowany backup, ten:
- przy użyciu klucza prywatnego i certyfikatu otworzy zamek przez BLE (w zasięgu radiowym) do czasu wygaśnięcia certyfikatu;
- przy użyciu PAK z zakresem `Mobile.ReadWrite` i `DeviceCertificate.Operate` (README:82-86) zarejestruje własny „telefon” i wygeneruje kolejne certyfikaty, czyli uzyska trwały dostęp do drzwi.

Pozytywne: brak `diagnostics.py` (`grep`: brak `async_get_config_entry_diagnostics`), więc „Download diagnostics” niczego nie ujawnia. PAK nie trafia do logów: nagłówek jest ustawiany w `cloud_api.py:26-32`, a nigdzie nie jest logowany.

**Rekomendacje:**
- Po instalacji zmienić PAK przez re-auth (`config_flow.py:170-190`, re-auth sprawdza tylko `GET /my/device/details`) na klucz **bez `Mobile.ReadWrite`**: `Device.Read`, `DeviceCertificate.Operate`, `DeviceActivity.Read`. Do odświeżania certyfikatu (`coordinator.py:1167-1186`) `Mobile.ReadWrite` nie jest potrzebne. Ustawić datę wygaśnięcia PAK, jeśli portal na to pozwala.
- Backupy HA tylko szyfrowane. Ograniczyć dostęp do `/config` (add-ony z dostępem do plików, Samba, SSH).

### M2. Brak wyrejestrowania „mobile” przy usuwaniu (Średnie)

**Co sprawdzono:** cykl życia rejestracji w Tedee.

**Wynik:** `cloud_api.py:136-139` definiuje `delete_mobile`, ale nic jej nie wywołuje (`grep delete_mobile` daje tylko definicję), a integracja nie ma `async_remove_entry`. Po usunięciu integracji „telefon” `tedee-ble-ha` zostaje na koncie Tedee z ważnym certyfikatem, a klucz prywatny może zostać w starych backupach.

**Rekomendacja:** przy deinstalacji ręcznie usunąć urządzenie „tedee-ble-ha” w aplikacji lub portalu Tedee. Opcjonalnie `async_remove_entry` → `delete_mobile`, ale to wymaga `Mobile.ReadWrite`, co koliduje z M1, więc lepiej usuwać ręcznie.

### M3. Wydanie ZIP nieodtwarzalne z taga (Średnie, supply chain)

**Co sprawdzono:** `hacs.json`, `release.sh`.

**Wynik:** `hacs.json:4-5` ustawia `"zip_release": true`, więc HACS pobiera `tedee_ble.zip` z GitHub Release. ZIP jest budowany **lokalnie na maszynie autora** (`release.sh:139-153`) z katalogu roboczego i nie powstaje w CI. Treść ZIP-a nie musi odpowiadać tagowi, a commity są podpisane kluczem SSH (`git commit -S`, `release.sh:125-129`), którego nie da się tu zweryfikować bez allowed signers. Zawartości ZIP-a z release'u upstream **nie sprawdzałem**: odczyt release'u upstream przez `gh` został zablokowany przez uprawnienia.

**Rekomendacja:** instalować z forka `sagan-dev/tedee_ble` z konkretnego, przejrzanego commita, np. kopiując `custom_components/tedee_ble` albo z własnego release'u forka. Nie instalować ZIP-a upstream z HACS i nie włączać auto-update HACS dla tego repo. Każdą aktualizację z upstream przeglądać jako diff.

### M4. Karta pokazywała ostatnie zdarzenie zamiast stanu (Średnie, naprawione)

**Wynik:** `www/tedee-lock-card.js:208-216` preferował atrybut `last_action` przed stanem encji. `last_action` zmienia się tylko przy zdarzeniach (`coordinator.py:560-616` nie aktualizuje go przy przejściu LOCKED→UNLOCKED wykrytym przez odczyt stanu, np. po ręcznym otwarciu kluczem przy zerwanym BLE). Karta mogła więc pokazywać zielone „Locked”, gdy encja miała `unlocked` albo `jammed`.

**Poprawka (commit „card: show the lock entity state…”):** stan encji jest nadrzędny, a `last_action` może tylko doprecyzować `unlocked` do `partially_unlocked`. `CARD_VERSION` 1.5.0 → 1.5.1, żeby przeglądarki nie używały starego skryptu.

### M5. Osierocony koordynator po nieudanym setupie (Średnie, naprawione)

**Wynik:** `coordinator.py:340-351`: gdy `_connect()` padał po zestawieniu łącza BLE (np. błąd handshake'u), `async_setup` rzucał `ConfigEntryNotReady`, nie rozłączając łącza i nie wyrejestrowując timera `async_track_time_interval` (`:334-338`). Callback rozłączenia (`:651-653` → `_on_disconnect` → `_schedule_reconnect`) dalej wskazywał na porzucony koordynator. Ten mógł się sam reconnectować i rywalizować z ponowną próbą HA o jedyne łącze z zamkiem. Timer firmware wyciekał przy każdej ponownej próbie.

**Poprawka (commit „coordinator: clean up after a failed setup”):** przed `ConfigEntryNotReady` wywoływane jest `async_shutdown()` (`_shutting_down`, anulowanie zadań, unsub timera, disconnect).

### L1. GitHub Actions (Niskie, naprawione)

**Co sprawdzono:** `.github/workflows/hassfest.yaml`, `validate.yaml`.

**Wynik:** brak `pull_request_target`, brak sekretów i brak kroków z `run:` na danych z PR. Akcje były jednak na zmiennych refach: `actions/checkout@v7`, `home-assistant/actions/hassfest@master`, `hacs/action@main` (semgrep `github-actions-mutable-action-tag`). `hassfest.yaml` nie ustawiał `permissions`, więc dostawał domyślny token.

**Poprawka:** przypięcie do SHA (`actions/checkout@3d3c42e…` = v7.0.1, `hassfest@86d4564…`, `hacs/action@1ebf01c…`), `permissions: contents: read` w hassfest, `persist-credentials: false`. Aktualizacje SHA trzeba będzie robić ręcznie albo przez Dependabota.

### L2. Zależności (Niskie, częściowo naprawione)

**Co sprawdzono:** `manifest.json` `requirements`, `requirements.txt`, PyPI, pip-audit.

**Wynik:**
- `manifest.json:16`: `bleak>=0.21`, `bleak-retry-connector>=3.0`. Oba to prawdziwe, popularne pakiety: `bleak` (Henrik Blidh) i `bleak-retry-connector` (J. Nick Koston, maintainer stosu Bluetooth HA). Obie są też zależnościami HA core, więc HA ich nie doinstalowuje. Typosquattingu brak. **Nie przypinam** dokładnych wersji: przypięcie w manifeście custom integration wymusiłoby inną wersję niż ta przypięta przez HA core i mogłoby zepsuć Bluetooth w HA. Dolne granice są zgodne z konwencją HA.
- `cryptography` i `httpx` są używane, ale nie ma ich w manifeście. Dostarcza je HA core.
- `tedee_lib/ble_esphome.py` importuje `habluetooth` i `bleak_esphome` (oba od J. Nick Koston), ale integracja go nie używa (import tylko w `cli.py:39`), więc jest martwym kodem w zainstalowanej paczce.
- pip-audit dla `requirements.txt` i manifestu (najnowsze wersje): brak podatności. Dla dolnej granicy `cryptography==41.0.0` jest 20 advisories (m.in. PYSEC-2023-254, PYSEC-2024-225, PYSEC-2026-35, PYSEC-2026-3553/3554, naprawione w ≤49.0.0). Dotyczy tylko `cli.py`.
- Brak vendored kodu firm trzecich. `tedee_lib/` to kod autora. Pliki binarne to tylko PNG (6 sztuk, bez danych za `IEND`).

**Poprawka:** `requirements.txt`: `cryptography>=49.0.0`.

### L3. Nadpisywanie MAC na podstawie nieuwierzytelnionej reklamy (Niskie)

**Wynik:** `coordinator.py:375-384`, `:445-451`, `:512-520`: gdy zapisany MAC nie jest widoczny, integracja szuka reklamy z UUID wyliczonym z numeru seryjnego (znanego publicznie, bo jest w reklamie) i **przed** handshake'iem zapisuje nowy MAC w config entry. Podszycie się pod zamek nie przejdzie (podpis w `ptls.py:335-340`), ale atakujący w zasięgu może trwale „przekierować” integrację na swój adres, co działa jak DoS do czasu, aż prawdziwy zamek znów się pojawi.

**Rekomendacja:** zapisywać nowy MAC dopiero po udanym `handshake()`.

### L4. 16-bitowy licznik nonce (Niskie, teoretyczne)

**Wynik:** `crypto.py:80-85` XOR-uje licznik tylko na 2 ostatnie bajty IV, więc `make_nonce(iv, 0) == make_nonce(iv, 65536)` (test PoC: PASSED). Przy >65535 wiadomościach w jednej sesji nonce AES-GCM by się powtórzył. W praktyce keep-alive co 45 s (`const.py:95`) daje ok. 2 tys. wiadomości na dobę, a zamek zamyka sesję po 24 h (`ptls.py:51,60`), więc limit jest nieosiągalny. To ograniczenie protokołu Tedee, nie tej implementacji.

**Rekomendacja:** w `encrypt()` rzucać błąd (wymuszając reconnect), gdy `send_counter >= 0xFFFF`.

### L5. Nieograniczone kolejki (Niskie)

`ble.py:70-72` i `ble_esphome.py:121-123` używają `asyncio.Queue()` bez `maxsize`. Kolejka PTLS TX nie jest opróżniana po handshake'u. Wrogi peer albo „burza duplikatów” może zwiększać zużycie pamięci. **Rekomendacja:** `maxsize` (np. 64) i odrzucanie najstarszych elementów.

### L6. Logowanie (Niskie)

**Co sprawdzono:** wszystkie wywołania `logger.*`, czy logują PAK, klucz prywatny, certyfikat albo dane sesji.

**Wynik:** PAK, klucza prywatnego, certyfikatu, sekretu ECDH ani kluczy sesji nie ma w logach (`ptls.py:269` loguje tylko długość sekretu). Na poziomie DEBUG logowane są surowe ramki BLE w hex (`ble.py:137-157`), w tym jawne pola handshake'u, które są publiczne, oraz zaszyfrowany ruch. Logowane są też odszyfrowane odpowiedzi komend (`lock_commands.py:216`) i notyfikacje z nazwą użytkownika (`coordinator.py:963`). `cloud_api.py:72-85` (`_require_result`) przy nieoczekiwanej odpowiedzi wkłada cały `result` do wyjątku, który jest logowany jako ERROR (`config_flow.py:381`). Certyfikat bez klucza prywatnego nie daje dostępu, więc ryzyko jest niskie.

**Rekomendacja:** nie włączać debug logów dla `custom_components.tedee_ble` na stałe. W `_require_result` logować tylko listę kluczy.

### L7. Dane osobowe (Info)

`cloud_api.py:141-180` pobiera 200 ostatnich wpisów aktywności (imiona użytkowników, aliasy PIN-ów klawiatury) i zapisuje mapę w config entry (`coordinator.py:1181`). `last_user` jest atrybutem encji (`lock.py:107-113`), więc trafia do historii recordera.

### L8. Autoryzacja lock/unlock/open (Niskie, konfiguracja HA)

**Co sprawdzono:** encję `lock`, usługi, auto-pull i zachowanie przy błędach.

**Wynik:**
- Integracja nie rejestruje własnych usług (`grep hass.services` nic nie zwraca). Działają standardowe `lock.lock/unlock/open` (`lock.py:121-136`), bez `code_format`. HA nie ma uprawnień per encja: każdy zalogowany użytkownik, także nie-admin, oraz każda integracja z wystawionymi encjami (Assist, Google/Alexa, HomeKit Bridge, webhooki/automatyzacje) może otworzyć drzwi. Karta wykonuje unlock/open jednym kliknięciem bez potwierdzenia (`tedee-lock-card.js:400-402`).
- `open` = pull spring, czyli fizyczne otwarcie drzwi. Opcja `auto_pull` jest domyślnie wyłączona (`config_flow.py:62-66`). Gdy jest wyłączona, unlock wysyła `UNLOCK_NO_PULL` (`coordinator.py:1112`).
- Zachowanie przy błędach nie przepuszcza: bez połączenia komendy rzucają `HomeAssistantError` (`coordinator.py:1143-1155`), a wynik inny niż SUCCESS daje `CommandError`. `is_locked` zwraca `None` (unknown), gdy encja jest niedostępna, trwa aktualizacja albo zamek nie jest skalibrowany (`lock.py:79-87`). Komendy są blokowane w trakcie aktualizacji firmware. Żadnego automatycznego unlocku w kodzie nie ma. Jedyna rzecz w kierunku fail-open to H1 (stan da się sfałszować) oraz to, że przez 15 s po zerwaniu łącza (`const.py:96`) encja pokazuje ostatni znany stan.

**Rekomendacja:** nie wystawiać encji zamka do asystentów głosowych i chmur. Kartę z przyciskami umieszczać tylko na dashboardach adminów. W automatyzacjach nie robić unlocku na podstawie warunków, które da się sfałszować.

### L9. CLI (Info)

`cli.py:81` zapisuje `config.json` (z `api_key`) bez `chmod`, a `cli.py:103-104` zapisuje klucz z `0o600`. Dotyczy tylko narzędzia deweloperskiego. CLI nie jest częścią integracji i nie należy go uruchamiać na produkcji.

### L10. Rejestracja zasobu Lovelace (Info)

`__init__.py:31-71` przy starcie serwuje `/tedee-ble/tedee-lock-card.js` jako plik statyczny (bez autoryzacji, ale to publiczny kod) i dopisuje go do zasobów Lovelace wszystkich dashboardów. Skrypt nie ładuje zewnętrznych zasobów (brak `fetch`/`import()`/zewnętrznych `src`). Nazwa encji i `last_user` są escapowane przez `_esc()` (`tedee-lock-card.js:375,384,406-411`), a pozostałe interpolacje pochodzą ze stałych map albo z `parseInt`. **XSS: brak.**

---

## Pozostałe punkty zakresu, w których nie znalazłem problemów

- **Wykonywanie kodu (pkt 3):** brak `eval`, `exec`, `subprocess`, `os.system`, `pickle`, `importlib`, `__import__` w całym repo (grep oraz bandit/semgrep `p/python`). Integracja nie pobiera kodu z sieci w runtime.
- **Sieć i TLS (pkt 4):** jedyny host to `https://api.tedee.com/api/v37` (`cloud_api.py:17`). `httpx.AsyncClient` działa z domyślną weryfikacją certyfikatu (nigdzie nie ma `verify=`), bez pinningu, który przy chmurowym API nie jest wymagany. Timeout to 30 s, a klient jest tworzony w executorze, żeby nie blokować pętli (`cloud_api.py:26-46`). W `config_flow` pojawia się jeszcze `portal.tedee.com`, ale tylko jako link w opisie formularza. Brak telemetrii i innych hostów.
- **PTLS (pkt 7):** efemeryczny ECDH P-256 dla każdej sesji (`ptls.py:214`), losowe 32 B z `os.urandom` (`:219`). Integracja weryfikuje `auth_data` (znacznik czasu, który sama wysłała), `hello_hash` i **podpis ECDSA zamka** kluczem `devicePublicKey` z chmury (`:317-340`), więc MITM nie zestawi sesji. Kluczami sesji są AES-GCM-128 z HMAC-SHA256 (schemat protokołu Tedee). Ochrona przed replay działa na licznikach: duplikaty z okna wstecz są odrzucane (`:514-532`), a „missed counters” mogą być użyte tylko raz (`:464-477`). Zaakceptowanie skoku do przodu o maks. 5 to kompromis pod proxy BLE, a każdy licznik i tak wymaga ważnego tagu GCM. Każdy etap ma timeout (`_read_ptls_frame`, 10 s, `:166-209`; `_send_command`, 10 s). Słabe miejsca to tylko H1 i L4.
- **Odporność (pkt 10):** backoff reconnectu 2 s…600 s (`const.py:90`), brak spinowania w gorącej pętli. Keep-alive co 45 s. `async_shutdown` anuluje wszystkie zadania. Dziurę przy nieudanym setupie zamyka M5. Nie znalazłem blokujących wywołań w pętli zdarzeń poza krótkim `pem_to_private_key` (µs). `BleakScanner.discover` w config flow (15 s) jest asynchroniczny.
- **Ruff `S`/`B`/`ASYNC`:** 18 trafień, wszystkie niskie lub stylistyczne: 15× `ASYNC109` (parametr `timeout`), `S101` (assert długości hello, `ptls.py:228`), `S110` (`coordinator.py:822`, try/except/pass przy disconnect), `B904`.
- **Bandit:** 3× Low (B110, B107 false positive dla `password: str = ""` w `ble_esphome.py:106`, B101). Brak Medium i High.
- **Semgrep:** 4 trafienia `github-actions-mutable-action-tag` (L1, naprawione). Poza tym nic, także w `p/secrets` (brak zahardkodowanych sekretów).
- **Testy repo:** repo nie ma testów jednostkowych. Uruchomiłem tylko własne testy PoC offline (4/4 PASSED, opisane w H1 i L4).

## Warunki instalacji (pytania do Michała, niczego z tego nie sprawdzałem)

1. Czy jest konto Tedee, na którym ten zamek jest **właścicielem/adminem**, i kto wygeneruje PAK w portal.tedee.com? Na setup potrzebne są zakresy `Device.Read`, `DeviceCertificate.Operate`, `Mobile.ReadWrite`, `DeviceActivity.Read`. Po setupie PAK należy zmienić przez re-auth na klucz bez `Mobile.ReadWrite` (M1). PAK wpisuje Michał w formularzu HA, nigdy przez wiadomość.
2. Jaki to model zamka (PRO / GO / GO 2 / PRO 2) i jaka wersja firmware?
3. Czy host HA ma adapter Bluetooth (lub proxy ESPHome BT z wolnym slotem połączenia) **w zasięgu zamka**? Integracja trzyma stałe połączenie z keep-alive co 45 s.
4. Czy zamek jest teraz sparowany z Tedee Bridge albo inną integracją (oficjalna `tedee` w HA)? Lock ma ograniczoną liczbę równoległych połączeń BLE.
5. Czy backupy HA są szyfrowane i kto ma dostęp do `/config`? Config entry daje dostęp do drzwi (M1).
6. Czy encja zamka ma być wystawiona do Assist/Google/HomeKit? Rekomendacja: nie (L8).
7. Czy włączyć opcję `auto_pull` (unlock = też fizyczne otwarcie drzwi)? Domyślnie jest wyłączona.
8. Czy akceptujesz H1 bez poprawki, czy najpierw poprawka i test na zamku?
9. Źródło instalacji: fork `sagan-dev/tedee_ble` z przejrzanego commita, nie HACS z upstream (M3).
