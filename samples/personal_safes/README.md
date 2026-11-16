# Personal Safes sample (synthetic)

`secrets-export.csv` has secrets in Delinea-style personal folders (`\Personal Folders\<display name>`),
and `config.json` marks them as personal, plus one folder that belongs to one named person.
With `../delinea_reports/lauserslist.csv` as the users list, Jane Smith's folders become `PER-jane.smith`
instead of abbreviations of her name. All names and passwords are made up.

    python -m imw convert -i secrets-export.csv --reference ../delinea_reports/lauserslist.csv -c config.json -o out
