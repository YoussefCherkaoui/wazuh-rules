# wazuh-rules

Regole, decoder e configurazioni personalizzate per [Wazuh](https://wazuh.com), scritte e collaudate da Youssef Cherkaoui, Wazuh Ambassador.

Ogni regola qui dentro nasce da un caso reale: un log da interpretare, un attacco da riconoscere, un falso positivo da silenziare.

## Struttura

| Cartella | Contenuto | Dove va sul manager |
| --- | --- | --- |
| `rules/` | Regole personalizzate (`*_rules.xml`) | `/var/ossec/etc/rules/` |
| `decoders/` | Decoder personalizzati (`*_decoder.xml`) | `/var/ossec/etc/decoders/` |
| `lists/` | Liste CDB (IP, utenti, hash) | `/var/ossec/etc/lists/` |
| `active-response/` | Script e configurazioni di risposta attiva | `/var/ossec/active-response/bin/` |
| `examples/` | Esempi commentati con log di prova, da copiare come punto di partenza | — |
| `tests/` | Casi di prova: evento, regola e risultato atteso | — |
| `scripts/` | Controlli automatici sul ruleset | — |

## Convenzioni

- **ID delle regole**: Wazuh riserva alle regole personalizzate l'intervallo 100000–120000. Qui:
  - 100000–100099: esempi in `examples/`
  - 100100 in poi: regole vere in `rules/`, un blocco di 100 ID per ogni file
- **Un file per argomento**: `rules/ssh_rules.xml`, `rules/fortinet_rules.xml`, con il decoder corrispondente in `decoders/`.
- **Ogni regola ha** una descrizione chiara, i gruppi corretti e, quando ha senso, l'ID della tecnica MITRE ATT&CK.
- **Ogni regola ha un log di prova**, nel commento sopra la regola o in `examples/`.

## Installazione

Sul Wazuh manager:

```bash
sudo cp rules/*_rules.xml /var/ossec/etc/rules/
sudo cp decoders/*_decoder.xml /var/ossec/etc/decoders/
sudo chown wazuh:wazuh /var/ossec/etc/rules/*.xml /var/ossec/etc/decoders/*.xml
sudo chmod 660 /var/ossec/etc/rules/*.xml /var/ossec/etc/decoders/*.xml
sudo systemctl restart wazuh-manager
```

## Prova di una regola

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Incolla il log di prova: `wazuh-logtest` mostra il decoder usato, i campi estratti e la regola che scatta con il suo livello.

## Controllo automatico

```bash
python3 scripts/check_ruleset.py
```

Lo script verifica che ogni file XML sia ben formato, che gli ID siano unici e che stiano nell'intervallo giusto.

```bash
python3 scripts/test_rules.py
```

Prova le condizioni `<field>` di ogni regola sugli eventi descritti in `tests/*.json`, compresi i casi che **non** devono scattare (per esempio un'eccezione aggirata). Controlla le regex della singola regola, non la catena di `if_sid`: la prova definitiva resta `wazuh-logtest` sul manager.

Entrambi gli script girano su GitHub Actions a ogni push e pull request.

## Regole disponibili

| File | Blocco ID | Regola | Livello | Descrizione | MITRE |
|---|---|---|---|---|---|
| `rules/windows_rundll32_rules.xml` | 100900–100999 | 100974 | 12 | `rundll32 url.dll,FileProtocolHandler` apre un URL http(s) (evento Windows 4688) | T1218.011 |
| `rules/windows_rundll32_rules.xml` | 100900–100999 | 100979 | 3 | Eccezione: `netbird-ui.exe` in `C:\Program Files\NetBird\` apre la pagina di aggiornamento `https://pkgs.netbird.io/windows/` | — |

### Windows: rundll32 che apre un URL (eccezione NetBird)

Spiegata anche in questo post su LinkedIn: [Un falso positivo non si risolve abbassando la regola](https://www.linkedin.com/feed/update/urn:li:activity:7531272622827872256/).

`rundll32` che apre un URL è una tecnica usata anche dagli attaccanti per eseguire contenuti tramite un binario fidato di Windows, quindi la regola 100974 resta a livello 12. Il client NetBird usa lo stesso meccanismo per aprire la sua pagina di aggiornamento nel browser.

Invece di disattivare o abbassare la regola, la 100979 la porta a livello 3 solo quando **entrambe** le condizioni sono vere:

- il processo padre è `netbird-ui.exe` nel suo **percorso completo** di installazione: un `netbird-ui.exe` qualsiasi copiato in una cartella scrivibile dall'utente (per esempio `%TEMP%\Netbird\`) non basta;
- la riga di comando apre **esattamente** `https://pkgs.netbird.io/windows/`, con l'espressione ancorata all'inizio (`^`): un URL che contiene il dominio solo nel percorso non passa.

Lo stesso comando lanciato da qualsiasi altro processo, o verso qualsiasi altro indirizzo, resta un alert di livello 12. Anche la pagina di login di NetBird resta un alert: se vuoi escluderla, aggiungi una regola figlia con l'indirizzo del tuo server NetBird.

Se NetBird è installato in un'altra cartella, adatta il percorso nella regola 100979.

**Requisiti:** audit della creazione dei processi su Windows (evento 4688) con la riga di comando inclusa negli eventi.

**Eventi di prova (anonimizzati):** `examples/netbird_rundll32_update_event.json` (aggiornamento, da cui nasce l'eccezione) e `examples/netbird_rundll32_url_event.json` (login).

**Casi di test:** `tests/windows_rundll32.json`: aggiornamento NetBird, login NetBird, `netbird-ui.exe` finto in `%TEMP%`, stesso comando da un altro processo, dominio NetBird nascosto nel percorso di un altro sito, rundll32 senza URL.
