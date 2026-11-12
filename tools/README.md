# Tools

`generate_synthetic_delinea.py` creates realistic **synthetic** Delinea Secret Server data, so the pipeline can be tested without access to Delinea. It writes three files:
- a multi-template export with Secret IDs (metadata only by default)
- a permissions report
- a matching pam2pc config

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
python -m pam2pc convert -i synthetic/delinea_export_synthetic.csv -p synthetic/delinea_permissions_synthetic.csv -c synthetic/mapping_config_synthetic.json -o synthetic_out
```
