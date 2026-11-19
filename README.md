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

Lo script verifica che ogni file XML sia ben formato, che gli ID siano unici e che stiano nell'intervallo giusto. Gira anche su GitHub Actions a ogni push e pull request.
