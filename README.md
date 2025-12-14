Python Network Audit Tool
=========================

Simple, small Python project to scan a host for open TCP ports and attempt basic service detection via banner grabbing.

Usage
-----

Run the CLI from the project root:

```bash
python main.py --target 127.0.0.1
```

Specify ports:

```bash
python main.py -t 192.168.1.10 -p 22,80,8000-8010
```

Save a report:

```bash
python main.py -t example.com -o report.txt
```

Notes
-----
- This is a lightweight educational tool. For robust scanning use established tools like nmap.
- Running port scans may be considered hostile activity on networks you don't own — only scan systems you are authorized to test.
