# Tools

`generate_synthetic_delinea.py` creates realistic **synthetic** Delinea Secret Server data, so the pipeline can be tested without access to Delinea. It writes three files:
- a multi-template export with Secret IDs (metadata only by default)
- a permissions report
- a matching Phase 1 config

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

Pass your real group names to make a rehearsal prove that CyberArk can find them. `--with-values` adds fake password values, to mimic a full export.
