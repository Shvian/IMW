# Personal Safes sample (synthetic)

`secrets-export.csv` has secrets in Delinea-style personal folders (`\Personal Folders\<display name>`),
and `config.json` marks them as personal, plus one folder that belongs to one named person.
With `../delinea_reports/lauserslist.csv` as the users list, Jane Smith's folders become `P-jane.smith`
instead of abbreviations of her name. `allsecrets.csv` gives the templates and `whatfolderscanalluserssee.csv` is a users report: Jane is Owner of her
folder, so her Safe membership matches the report; the others are added as owners with a note.
All names and passwords are made up.

    python -m imw convert -i secrets-export.csv -i allsecrets.csv --reference ../delinea_reports/lauserslist.csv \
        -p whatfolderscanalluserssee.csv -c config.json -o out
