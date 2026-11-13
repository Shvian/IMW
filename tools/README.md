# Tools

## generate_sample_pack.py: a ready-to-try sample workspace

```
python tools/generate_sample_pack.py --out sample_workspace
python -m imw ui --workspace sample_workspace
```

The pack is a Workbench workspace. It holds a starter `config.json` and an `inbox/` with four files:
- a Delinea multi-template export, about 400 secrets
- a Delinea permissions file
- a KeePass XML export, 60 entries
- an Excel inventory, 120 rows

Everything in it is fake. It deliberately contains the problems a real migration has, so every review list has something in it:
- long Safe names, including two that collide once shortened
- invalid characters in names
- record types that have no platform
- missing usernames and addresses
- empty secrets and SSH keys
- attachments
- duplicate names
- folders with no permissions, and secret-level overrides

`SAMPLE_DATA_README.txt` in the pack lists the details and some things to try. You can set the volumes with `--delinea`, `--keepass` and `--excel`.

## generate_synthetic_delinea.py: Delinea only, for volume testing

`generate_synthetic_delinea.py` creates realistic **synthetic** Delinea Secret Server data, so the pipeline can be tested without access to Delinea. It writes three files:
- a multi-template export with Secret IDs (metadata only by default)
- a permissions report
- a matching Workbench config

The data deliberately includes the messy cases: an unmapped template, duplicate names, missing addresses, unpermissioned folders, mixed permissions and secret-level overrides.

```
python generate_synthetic_delinea.py --secrets 2000 --out synthetic --groups "CORP\PAM-Windows-Admins" "CORP\PAM-Unix-Admins"
```

Group order for `--groups`:
1. Windows admins
2. Unix admins
3. DBA
4. Web ops
5. Network
6. Payments app owners
7. Storefront app owners
8. Helpdesk

`--with-values` adds fake password values, to mimic a full export. Convert the output with:

```
python -m imw convert -i synthetic/delinea_export_synthetic.csv -p synthetic/delinea_permissions_synthetic.csv -c synthetic/mapping_config_synthetic.json -o synthetic_out
```
