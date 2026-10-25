#!/usr/bin/env python3
"""REA P248: one independently approved owner-signed NEW MCP certification.

Only the original REA public JavaScript runtime reconciliation example is
embedded. The sample is source-owned, not a customer's app.
No network, GitHub operations, RSA encryption, VPS access or REA MCP call.
Owner Ed25519 private PEM remains on Android Termux. The signer itself
MUST NOT be interpreted as a certification, and never silently signs.
"""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import tempfile

TOOL = "reconcile_javascript_runtime"
OWNER_FINGERPRINT_SHA256_DER = "99580a4806703661ca38f75a3cb95e47d46e32228cf89d5aa7ab55e95a4e25b4"
PUBLIC_INPUT_SHA256 = "22f801adca089b79d95fdeeac1edfb6b8a5ffc030fe7cd664f066cca45dc21a1"
PUBLIC_INPUT_BYTES = 8785
PUBLIC_SOURCE_GIT_BLOB = "8a535c63ff0989bfd8acfd49d196ecb690c11104"
PUBLIC_SOURCE_GIT_HEAD = "8e9a7ee295667f8e23aea9d18af6eee4363d2032"
APPROVAL = "AUTORIZO_OPERACAO_SENSIVEL"
REASON = (
    "Owner expressly authorizes exactly one original REA MCP "
    "reconcile_javascript_runtime evaluation of the public source-owned "
    "static/runtime JavaScript Evidence fixture. The operation is permitted "
    "to append its derived, clearly synthetic certification Evidence to "
    "the existing session without erasing, overwriting, importing or "
    "changing existing six historical Evidence records; no binar"
    "y lifecycle, debugger, browser, customer app, target execution, "
    "remote connections or device access."
)
PUBLIC_INPUT_B64 = (
    "eyJydW50aW1lX29ic2VydmF0aW9ucyI6W3siYW5hbHlzaXNfcHJvZmlsZSI6bnVsbCwiYXV0aG9yaXR5IjoiZXh0ZXJuYWwtc2"
    "VydmljZSIsImNvbmZpZGVuY2UiOiJvYnNlcnZlZCIsImVudmlyb25tZW50IjpudWxsLCJldmlkZW5jZV9pZCI6ImV2XzY1Y2Vj"
    "ZjU2NDM0MmZkNzdjYzZhOTQ0NmI4ODI0ZDVhZTcwMmVjMmI1OWRlYzI4NGIzODBjNTk5OGU4Y2JjYTIiLCJldmlkZW5jZV9saW"
    "5rcyI6W10sImxpbWl0YXRpb25zIjpbIkFydGlmYWN0IGlkZW50aXR5IGlzIHVuYXZhaWxhYmxlIGZvciB0aGlzIG9ic2VydmF0"
    "aW9uLiJdLCJsb2NhdGlvbnMiOltdLCJub3JtYWxpemVkX3Jlc3VsdCI6eyJicm93c2VyIjp7ImpzX3ZlcnNpb24iOiIxIiwicH"
    "JvZHVjdCI6IkVsZWN0cm9uL2V4YW1wbGUiLCJwcm90b2NvbF92ZXJzaW9uIjoiMS4zIiwicmV2aXNpb24iOiJleGFtcGxlIiwi"
    "dXNlcl9hZ2VudCI6IkVsZWN0cm9uIGV4YW1wbGUifSwiY2FwdHVyZV93aW5kb3ciOnsiZW5kZWRfYXQiOiIyMDI2LTA3LTE1VD"
    "AwOjAwOjAwLjEwMFoiLCJvYnNlcnZhdGlvbl9tcyI6MTAwLCJzdGFydGVkX2F0IjoiMjAyNi0wNy0xNVQwMDowMDowMC4wMDBa"
    "In0sImNvbXBsZXRlbmVzcyI6eyJhdHRhY2hfbGltaXRlZF9zZWN0aW9ucyI6W10sImNvbmRpdGlvbnMiOlsiY29tcGxldGVfd2"
    "l0aGluX3dpbmRvdyJdLCJkcm9wcGVkX2V2ZW50cyI6eyJjb25zb2xlX2V2ZW50cyI6MCwibmV0d29ya19yZXF1ZXN0cyI6MCwi"
    "c2NyaXB0cyI6MCwidGltZWxpbmVfZXZlbnRzIjowLCJ0b3RhbCI6MCwid2VibWNwX3Rvb2xzIjowLCJ3ZWJzb2NrZXRfY29ubm"
    "VjdGlvbnMiOjAsIndlYnNvY2tldF9mcmFtZXMiOjB9LCJleGNsdWRlZCI6W10sInBvbGljeV9maWx0ZXJlZF9zZWN0aW9ucyI6"
    "W10sInN0YXR1cyI6ImNvbXBsZXRlX3dpdGhpbl93aW5kb3ciLCJ0cnVuY2F0ZWRfc2VjdGlvbnMiOltdLCJ1bmF2YWlsYWJsZV"
    "9zZWN0aW9ucyI6W119LCJkb20iOnsibm9kZXMiOltdLCJ0b3RhbF9ub2RlcyI6MH0sImZyYW1lcyI6W10sImxpbWl0YXRpb25z"
    "IjpbIkV4YW1wbGUgcGFzc2l2ZSBjYXB0dXJlLiJdLCJyZXNvdXJjZXMiOltdLCJzY3JpcHRzIjp7Iml0ZW1zIjpbeyJjZHBfaG"
    "FzaCI6ImV4YW1wbGUiLCJmaWxlX3BhdGgiOiIvQXBwbGljYXRpb25zL0V4YW1wbGUuYXBwL0NvbnRlbnRzL1Jlc291cmNlcy9h"
    "cHAvcmVuZGVyZXIuanMiLCJmcmFtZV9pZCI6bnVsbCwiaXNfbW9kdWxlIjp0cnVlLCJsYW5ndWFnZSI6IkphdmFTY3JpcHQiLC"
    "JsZW5ndGgiOjI5LCJzY3JpcHRfa2V5IjoiZWxlY3Ryb25fc2NyaXB0XzQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0"
    "NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQiLCJzb3VyY2UiOnsiYXJ0aWZhY3QiOnsiYnl0ZXMiOjI5LCJjaGFyc2"
    "V0IjoidXRmLTgiLCJtZWRpYV90eXBlIjoidGV4dC9qYXZhc2NyaXB0Iiwic2hhMjU2IjoiYzRjMGQ3NjBhNGM4NGYwZTE4MmRl"
    "OTlmNmVmODllZjEwODMxZjgxNzBlNDg2YzRkNGJkOTM0OTI0MTUxYmE2NCIsInRleHQiOiJleHBvcnQgY29uc3QgZXhhbXBsZS"
    "A9IHRydWU7XG4ifSwiaW5jbHVkZWQiOnRydWV9fV0sInRvdGFsIjoxfSwidGFyZ2V0Ijp7ImF0dGFjaGVkIjpmYWxzZSwiZmls"
    "ZV9wYXRoIjoiL0FwcGxpY2F0aW9ucy9FeGFtcGxlLmFwcC9Db250ZW50cy9SZXNvdXJjZXMvYXBwL2luZGV4Lmh0bWwiLCJ0YX"
    "JnZXRfaWQiOiJleGFtcGxlLXRhcmdldCIsInRpdGxlIjoiRXhhbXBsZSIsInR5cGUiOiJwYWdlIn0sIndvcmtlcnMiOltdfSwi"
    "b3BlcmF0aW9uIjoiaW5zcGVjdF9lbGVjdHJvbl9wYWdlIiwicGFyYW1ldGVycyI6eyJjZHBfZW5kcG9pbnQiOiJodHRwOi8vMT"
    "I3LjAuMC4xOjkyMjMiLCJpbmNsdWRlX3NjcmlwdF9zb3VyY2VzIjp0cnVlLCJ0YXJnZXRfaWQiOiJleGFtcGxlLXRhcmdldCJ9"
    "LCJwcmVkaWNhdGVfdHlwZSI6InJlYS5lbGVjdHJvbi1wYWdlLWluc3BlY3Rpb24iLCJwcm92aWRlciI6eyJpZCI6InJlYS1jZH"
    "AtZWxlY3Ryb24iLCJuYW1lIjoiUkVBIEVsZWN0cm9uIGZpbGUtcGFnZSBDRFAgb2JzZXJ2YXRpb24gcHJvdmlkZXIiLCJ2ZXJz"
    "aW9uIjoiMSJ9LCJyYXdfcmVzdWx0IjpudWxsLCJyZWxhdGlvbnNoaXBfY292ZXJhZ2UiOm51bGwsInN1YmplY3QiOm51bGx9XS"
    "wic3RhdGljX2xheWVycyI6W3siYW5hbHlzaXMiOnsiYW5hbHlzaXNfcHJvZmlsZSI6bnVsbCwiYXV0aG9yaXR5Ijoic2hpcHBl"
    "ZC1hcnRpZmFjdCIsImNvbmZpZGVuY2UiOiJkZXJpdmVkIiwiZW52aXJvbm1lbnQiOm51bGwsImV2aWRlbmNlX2lkIjoiZXZfNW"
    "RiZDExMjhlZTBjNWE0ODVmMDRiMjg0ZTJjMGYxNjQ2OTU2YjkwMjQ0YzU4ZDZmMDBmOWRhM2Q1NTQ1NDlhNCIsImV2aWRlbmNl"
    "X2xpbmtzIjpbXSwibGltaXRhdGlvbnMiOltdLCJsb2NhdGlvbnMiOltdLCJub3JtYWxpemVkX3Jlc3VsdCI6eyJmb3JtYXQiOi"
    "JkaXJlY3RvcnkiLCJncmFwaCI6eyJjb3ZlcmFnZSI6eyJsaW1pdHMiOltdLCJvbWl0dGVkX2NvdW50IjowLCJzdGF0dXMiOiJj"
    "b21wbGV0ZSIsInRydW5jYXRlZCI6ZmFsc2V9LCJlZGdlcyI6W10sImdyYXBoX2lkIjoiamFnXzc0N2Q0NTU3ODU0OTRjMTI5NW"
    "UyYWI3MTAyYjZiMTQ2YmY2NjExZWYxZWIxOWZhODJiYTNlNzgxM2M1OWNjZTEiLCJsaW1pdGF0aW9ucyI6W10sIm5vZGVzIjpb"
    "eyJpZGVudGl0eSI6eyJzaGEyNTYiOiJjNGMwZDc2MGE0Yzg0ZjBlMTgyZGU5OWY2ZWY4OWVmMTA4MzFmODE3MGU0ODZjNGQ0Ym"
    "Q5MzQ5MjQxNTFiYTY0Iiwic3RhYmlsaXR5IjoiZ2xvYmFsLWV4YWN0Iiwic3RyYXRlZ3kiOiJjb250ZW50LWRpZ2VzdCJ9LCJr"
    "aW5kIjoiamF2YXNjcmlwdC1hc3NldCIsIm5vZGVfaWQiOiJqYWdfbm9kZV8zYzgyZGE1NDkyZDkwZWI1YjBiZWU0MWMxYTk5NG"
    "Q4OGI3YmE5OGMwYjQ5NTUyNzBkNzBlNTdhNzZlMjI0YzJlIiwib2JzZXJ2YXRpb25zIjpbeyJldmlkZW5jZSI6eyJhcnRpZmFj"
    "dCI6eyJhcnRpZmFjdF9pZCI6ImFydF9jNGMwZDc2MGE0Yzg0ZjBlMTgyZGU5OWY2ZWY4OWVmMTA4MzFmODE3MGU0ODZjNGQ0Ym"
    "Q5MzQ5MjQxNTFiYTY0IiwiYXZhaWxhYmxlIjp0cnVlLCJzaGEyNTYiOiJjNGMwZDc2MGE0Yzg0ZjBlMTgyZGU5OWY2ZWY4OWVm"
    "MTA4MzFmODE3MGU0ODZjNGQ0YmQ5MzQ5MjQxNTFiYTY0In0sImF1dGhvcml0eSI6ImFydGlmYWN0LWJ5dGVzIiwiY29uZmlkZW"
    "5jZSI6ImV4YWN0IiwiY292ZXJhZ2UiOnsibGltaXRzIjpbXSwib21pdHRlZF9jb3VudCI6MCwic3RhdHVzIjoiY29tcGxldGUi"
    "LCJ0cnVuY2F0ZWQiOmZhbHNlfSwiZXZpZGVuY2VfaWRzIjpbXSwiZXh0cmFjdG9yIjp7ImV4ZWN1dGFibGVfc2hhMjU2IjpudW"
    "xsLCJuYW1lIjoicmVhLWphdmFzY3JpcHQtYXBwbGljYXRpb24iLCJvcGVyYXRpb24iOiJpbnZlbnRvcnktcmVsZXZhbnQtZmls"
    "ZSIsInZlcnNpb24iOiIxIn0sImxpbWl0YXRpb25zIjpbXSwibG9jYXRpb24iOnsiYXZhaWxhYmxlIjp0cnVlLCJ2YWx1ZSI6ey"
    "JraW5kIjoiYXJ0aWZhY3QtcGF0aCIsInBhdGgiOiJyZW5kZXJlci5qcyJ9fSwic3RhdGUiOiJvYnNlcnZlZCJ9LCJpZGVudGlm"
    "aWVyX3N0cmF0ZWd5Ijp7InN0YWJpbGl0eSI6Im9ic2VydmF0aW9uLWV4YWN0Iiwic3RyYXRlZ3kiOiJzZW1hbnRpYy1jb250ZW"
    "50LXNoYTI1NiJ9LCJsYWJlbCI6InJlbmRlcmVyLmpzIiwib2JzZXJ2YXRpb25faWQiOiJqYWdfb2JzZXJ2YXRpb25fZmNhMDA5"
    "MjY2ZDBjNWVjODU2ZTAzMzU4ZGY1ZWI3MGYzMzk2NTVmNzc3MjAyNmU4MmY5ZTg1MTUxZTczYmQ4NSIsInByb3BlcnRpZXMiOn"
    "siYnl0ZXMiOjI5LCJwYXRoIjoicmVuZGVyZXIuanMifSwic291cmNlX21hcF9yZWZlcmVuY2UiOm51bGx9XX1dLCJyb290X25v"
    "ZGVfaWRzIjpbImphZ19ub2RlXzNjODJkYTU0OTJkOTBlYjViMGJlZTQxYzFhOTk0ZDg4YjdiYTk4YzBiNDk1NTI3MGQ3MGU1N2"
    "E3NmUyMjRjMmUiXSwic2NoZW1hIjoiSmF2YVNjcmlwdEFwcGxpY2F0aW9uR3JhcGgifSwiaW5wdXRfcGF0aCI6Ii9BcHBsaWNh"
    "dGlvbnMvRXhhbXBsZS5hcHAvQ29udGVudHMvUmVzb3VyY2VzL2FwcCIsImludGVncml0eV9jb250cmFkaWN0aW9ucyI6W10sIm"
    "ludmVudG9yeV9ncmFwaF9zaGEyNTYiOiIzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMz"
    "MzMzMzMzMzMzMzMzMzMzIiwiaW52ZW50b3J5X21hbmlmZXN0X2lkIjoiYWdtXzIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj"
    "IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIiLCJsaW1pdGF0aW9ucyI6W10sInJvb3RfYXJ0aWZhY3Rfc2hh"
    "MjU2IjoiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMSIsIn"
    "NlbWFudGljX2dyYXBoIjp7ImFwcGxpY2F0aW9uX2dyYXBoX2lkIjoiamFnXzc0N2Q0NTU3ODU0OTRjMTI5NWUyYWI3MTAyYjZi"
    "MTQ2YmY2NjExZWYxZWIxOWZhODJiYTNlNzgxM2M1OWNjZTEiLCJjb3ZlcmFnZSI6eyJmYW1pbGllcyI6W3siZmFtaWx5IjoiYm"
    "91bmRhcnkiLCJvbWl0dGVkX3JlbGF0aW9ucyI6MCwicmV0YWluZWRfcmVsYXRpb25zIjowLCJzdGF0dXMiOiJ1bmtub3duIiwi"
    "dW5rbm93bl9pZHMiOltdfSx7ImZhbWlseSI6ImNhbGwtZmxvdyIsIm9taXR0ZWRfcmVsYXRpb25zIjowLCJyZXRhaW5lZF9yZW"
    "xhdGlvbnMiOjAsInN0YXR1cyI6InVua25vd24iLCJ1bmtub3duX2lkcyI6W119LHsiZmFtaWx5IjoiY2hpbGQtcHJvY2VzcyIs"
    "Im9taXR0ZWRfcmVsYXRpb25zIjowLCJyZXRhaW5lZF9yZWxhdGlvbnMiOjAsInN0YXR1cyI6InVua25vd24iLCJ1bmtub3duX2"
    "lkcyI6W119LHsiZmFtaWx5IjoiY2xvc3VyZSIsIm9taXR0ZWRfcmVsYXRpb25zIjowLCJyZXRhaW5lZF9yZWxhdGlvbnMiOjAs"
    "InN0YXR1cyI6InVua25vd24iLCJ1bmtub3duX2lkcyI6W119LHsiZmFtaWx5IjoiY29uZmlndXJhdGlvbiIsIm9taXR0ZWRfcm"
    "VsYXRpb25zIjowLCJyZXRhaW5lZF9yZWxhdGlvbnMiOjAsInN0YXR1cyI6InVua25vd24iLCJ1bmtub3duX2lkcyI6W119LHsi"
    "ZmFtaWx5IjoiZGF0YS1mbG93Iiwib21pdHRlZF9yZWxhdGlvbnMiOjAsInJldGFpbmVkX3JlbGF0aW9ucyI6MCwic3RhdHVzIj"
    "oidW5rbm93biIsInVua25vd25faWRzIjpbXX0seyJmYW1pbHkiOiJldmVudCIsIm9taXR0ZWRfcmVsYXRpb25zIjowLCJyZXRh"
    "aW5lZF9yZWxhdGlvbnMiOjAsInN0YXR1cyI6InVua25vd24iLCJ1bmtub3duX2lkcyI6W119LHsiZmFtaWx5Ijoib2JqZWN0LW"
    "Zsb3ciLCJvbWl0dGVkX3JlbGF0aW9ucyI6MCwicmV0YWluZWRfcmVsYXRpb25zIjowLCJzdGF0dXMiOiJ1bmtub3duIiwidW5r"
    "bm93bl9pZHMiOltdfSx7ImZhbWlseSI6InByb21pc2Utb3duZXJzaGlwIiwib21pdHRlZF9yZWxhdGlvbnMiOjAsInJldGFpbm"
    "VkX3JlbGF0aW9ucyI6MCwic3RhdHVzIjoidW5rbm93biIsInVua25vd25faWRzIjpbXX0seyJmYW1pbHkiOiJyZXF1ZXN0Iiwi"
    "b21pdHRlZF9yZWxhdGlvbnMiOjAsInJldGFpbmVkX3JlbGF0aW9ucyI6MCwic3RhdHVzIjoidW5rbm93biIsInVua25vd25faW"
    "RzIjpbXX0seyJmYW1pbHkiOiJyZXNvdXJjZS1saWZlY3ljbGUiLCJvbWl0dGVkX3JlbGF0aW9ucyI6MCwicmV0YWluZWRfcmVs"
    "YXRpb25zIjowLCJzdGF0dXMiOiJ1bmtub3duIiwidW5rbm93bl9pZHMiOltdfSx7ImZhbWlseSI6InRpbWVyIiwib21pdHRlZF"
    "9yZWxhdGlvbnMiOjAsInJldGFpbmVkX3JlbGF0aW9ucyI6MCwic3RhdHVzIjoidW5rbm93biIsInVua25vd25faWRzIjpbXX1d"
    "LCJsaW1pdHMiOltdLCJvbWl0dGVkX25vZGVzIjowLCJvbWl0dGVkX3JlbGF0aW9ucyI6MCwic3RhdHVzIjoidW5rbm93biIsIn"
    "RydW5jYXRlZCI6ZmFsc2V9LCJldmlkZW5jZV9jb250ZXh0cyI6W3siYXJ0aWZhY3QiOnsiYXJ0aWZhY3RfaWQiOiJhcnRfYzRj"
    "MGQ3NjBhNGM4NGYwZTE4MmRlOTlmNmVmODllZjEwODMxZjgxNzBlNDg2YzRkNGJkOTM0OTI0MTUxYmE2NCIsImF2YWlsYWJsZS"
    "I6dHJ1ZSwic2hhMjU2IjoiYzRjMGQ3NjBhNGM4NGYwZTE4MmRlOTlmNmVmODllZjEwODMxZjgxNzBlNDg2YzRkNGJkOTM0OTI0"
    "MTUxYmE2NCJ9LCJhdXRob3JpdHkiOiJhcnRpZmFjdC1ieXRlcyIsImNvbmZpZGVuY2UiOiJleGFjdCIsImNvbnRleHRfaWQiOi"
    "Jqc3JnX2V2aWRlbmNlXzliMmQyOTY0Yjg3YTNmN2FkMzQwNDhhYTI3ZmNmNWI1MjA2NTE3NmRlZjBmZmI2MTUyNjBmNGIxODU4"
    "MjhmZTciLCJjb3ZlcmFnZSI6eyJsaW1pdHMiOltdLCJvbWl0dGVkX2NvdW50IjowLCJzdGF0dXMiOiJjb21wbGV0ZSIsInRydW"
    "5jYXRlZCI6ZmFsc2V9LCJldmlkZW5jZV9pZHMiOltdLCJleHRyYWN0b3IiOnsiZXhlY3V0YWJsZV9zaGEyNTYiOm51bGwsIm5h"
    "bWUiOiJyZWEtamF2YXNjcmlwdC1hcHBsaWNhdGlvbiIsIm9wZXJhdGlvbiI6ImludmVudG9yeS1yZWxldmFudC1maWxlIiwidm"
    "Vyc2lvbiI6IjEifSwibGltaXRhdGlvbnMiOltdLCJzdGF0ZSI6Im9ic2VydmVkIn1dLCJmaW5nZXJwcmludHMiOltdLCJncmFw"
    "aF9pZCI6ImpzcmdfMzA2YTZiNThlM2Y5YjkzYmUyYjExMDBmNmVmZjhkNzNjNDE5OTczNTU2MjRkNmZiMmM2YzdkY2EwZTgxND"
    "I4MCIsImxpbWl0YXRpb25zIjpbIlNlbWFudGljIHJlbGF0aW9ucyBhcmUgdW5hdmFpbGFibGUgaW4gdGhpcyBtaW5pbWFsIGV4"
    "YW1wbGUuIl0sIm5vZGVzIjpbeyJhcHBsaWNhdGlvbl9ub2RlX2lkcyI6WyJqYWdfbm9kZV8zYzgyZGE1NDkyZDkwZWI1YjBiZW"
    "U0MWMxYTk5NGQ4OGI3YmE5OGMwYjQ5NTUyNzBkNzBlNTdhNzZlMjI0YzJlIl0sImV2aWRlbmNlIjp7ImNvbnRleHRfaWQiOiJq"
    "c3JnX2V2aWRlbmNlXzliMmQyOTY0Yjg3YTNmN2FkMzQwNDhhYTI3ZmNmNWI1MjA2NTE3NmRlZjBmZmI2MTUyNjBmNGIxODU4Mj"
    "hmZTciLCJsb2NhdGlvbiI6eyJhdmFpbGFibGUiOnRydWUsInZhbHVlIjp7ImtpbmQiOiJhcnRpZmFjdC1wYXRoIiwicGF0aCI6"
    "InJlbmRlcmVyLmpzIn19fSwiZnVuY3Rpb25fbm9kZV9pZCI6bnVsbCwiaWRlbnRpdHkiOnsiYXJ0aWZhY3Rfc2hhMjU2IjoiMT"
    "ExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMSIsIm1vZHVsZV9w"
    "YXRoIjoicmVuZGVyZXIuanMiLCJyb2xlX2tleSI6ImV4YW1wbGUtbW9kdWxlIiwic291cmNlX3JhbmdlIjpudWxsfSwia2luZC"
    "I6Im1vZHVsZSIsImxhYmVsIjoicmVuZGVyZXIuanMiLCJub2RlX2lkIjoianNyZ19ub2RlXzk0NzY2MDJmMWY3NDQzM2EyYmQz"
    "ZGFkYjA0MGEyNTczNGQyMDNiOGY4MzFiMzFhOGQ5NmY3ZWZkZmM1Y2Q2NmEiLCJwcm9wZXJ0aWVzIjp7fX1dLCJyZWxhdGlvbn"
    "MiOltdLCJyb290X2FydGlmYWN0X3NoYTI1NiI6IjExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx"
    "MTExMTExMTExMTExMTExMTExMTEiLCJyb290X25vZGVfaWRzIjpbImpzcmdfbm9kZV85NDc2NjAyZjFmNzQ0MzNhMmJkM2RhZG"
    "IwNDBhMjU3MzRkMjAzYjhmODMxYjMxYThkOTZmN2VmZGZjNWNkNjZhIl0sInNjaGVtYSI6IkphdmFTY3JpcHRTZW1hbnRpY1Jl"
    "bGF0aW9uR3JhcGgiLCJ1bmtub3ducyI6W119LCJzdGF0aXN0aWNzIjp7ImZpbmRpbmdzIjowLCJpbnZhbGlkX3V0ZjhfZmlsZX"
    "MiOjAsIm1vZHVsZXMiOjAsIm5lc3RlZF9hc2FyX2NvbnRhaW5lcnMiOjAsInBhcnNlX2ZhaWx1cmVzIjowLCJwYXJzZWRfamF2"
    "YXNjcmlwdF9maWxlcyI6MSwicmVsZXZhbnRfZmlsZXMiOjEsInNraXBwZWRfamF2YXNjcmlwdF9maWxlcyI6MCwidGV4dF9ieX"
    "Rlc19yZWFkIjoyOSwidmlzaXRlZF9hc3Rfbm9kZXMiOjF9LCJzdW1tYXJ5Ijp7ImJyb3dzZXJfd2luZG93cyI6MCwiY29udGV4"
    "dF9icmlkZ2VfYXBpcyI6MCwiZXhwbGljaXRfd2ViX3ByZWZlcmVuY2VzIjowLCJleHBvc2VkX2FwaV9tZW1iZXJzIjowLCJpcG"
    "MiOnsiYW1iaWd1b3VzX3JlbmRlcmVyX3RyYW5zbWlzc2lvbnMiOjAsImR5bmFtaWNfY2hhbm5lbF9vcGVyYXRpb25zIjowLCJs"
    "aXRlcmFsX2NoYW5uZWxzIjowLCJtYWluX2hhbmRsZXJzIjowLCJvcGVyYXRpb25zIjowLCJwYWlyZWRfcmVuZGVyZXJfdHJhbn"
    "NtaXNzaW9ucyI6MCwicmVuZGVyZXJfbGlzdGVuZXJzIjowLCJyZW5kZXJlcl90cmFuc21pc3Npb25zIjowLCJ1bnBhaXJlZF9s"
    "aXRlcmFsX3JlbmRlcmVyX3RyYW5zbWlzc2lvbnMiOjB9LCJuYXRpdmVfYWRkb25fYmluZGluZ3MiOjAsInByZWxvYWRfZW50cn"
    "lwb2ludHMiOjAsInJlc29sdmVkX25hdGl2ZV9hZGRvbl9iaW5kaW5ncyI6MCwicmVzb2x2ZWRfdXRpbGl0eV9lbnRyeXBvaW50"
    "cyI6MCwic2VuZGVyX3ZhbGlkYXRpb25fb2JzZXJ2YXRpb25zIjowLCJ1dGlsaXR5X3Byb2Nlc3NlcyI6MH19LCJvcGVyYXRpb2"
    "4iOiJhbmFseXplX2phdmFzY3JpcHRfYXBwbGljYXRpb24iLCJwYXJhbWV0ZXJzIjp7fSwicHJlZGljYXRlX3R5cGUiOiJyZWEu"
    "amF2YXNjcmlwdC1hcHBsaWNhdGlvbi1hbmFseXNpcyIsInByb3ZpZGVyIjp7ImlkIjoicmVhLWphdmFzY3JpcHQtYXBwbGljYX"
    "Rpb24iLCJuYW1lIjoiUkVBIEphdmFTY3JpcHQgYXBwbGljYXRpb24gYW5hbHl6ZXIiLCJ2ZXJzaW9uIjoiMSJ9LCJyYXdfcmVz"
    "dWx0IjpudWxsLCJyZWxhdGlvbnNoaXBfY292ZXJhZ2UiOm51bGwsInN1YmplY3QiOnsiYXJjaGl0ZWN0dXJlIjpudWxsLCJkaW"
    "dlc3QiOnsic2hhMjU2IjoiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx"
    "MTExMTExMSJ9LCJmb3JtYXQiOiJkaXJlY3RvcnkiLCJsb2NhbF9wYXRoIjoiL0FwcGxpY2F0aW9ucy9FeGFtcGxlLmFwcC9Db2"
    "50ZW50cy9SZXNvdXJjZXMvYXBwIiwibmFtZSI6ImFwcCJ9fX1dfQ=="
)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


def load_source_example():
    raw = base64.b64decode(PUBLIC_INPUT_B64, validate=True)
    if len(raw) != PUBLIC_INPUT_BYTES:
        raise RuntimeError("Original source sample byte size changed")
    value = json.loads(raw)
    if hashlib.sha256(canonical(value)).hexdigest() != PUBLIC_INPUT_SHA256:
        raise RuntimeError("Original REA source sample digest mismatch")
    if (set(value) != {"static_layers", "runtime_observations"} or
        len(value["static_layers"]) != 1 or
        len(value["runtime_observations"]) != 1):
        raise RuntimeError("Unexpected original sample shape")
    return value


def owner_keys():
    folder = Path.home() / ".rea-owner"
    private = folder / "rea-owner-private.pem"
    public = folder / "rea-owner-public.pem"
    for path in (folder, private, public):
        if not path.exists() or path.is_symlink():
            raise RuntimeError("Owner key folder / PEM missing or symlink")
    for path in (private, public):
        state = path.stat()
        if (not stat.S_ISREG(state.st_mode) or
            stat.S_IMODE(state.st_mode) & 0o077):
            raise RuntimeError("Owner PEM must have private file permissions")
    digest = hashlib.sha256(subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(public),
         "-outform", "DER"], capture_output=True, check=True,
    ).stdout).hexdigest()
    if digest != OWNER_FINGERPRINT_SHA256_DER:
        raise RuntimeError("Wrong owner key! Fingerprint mismatch")
    return folder, private, public


def main():
    os.umask(0o077)
    args = load_source_example()
    directory, private, public = owner_keys()
    nonce = secrets.token_hex(16)
    expiry = (datetime.now(timezone.utc) +
              timedelta(minutes=45)).strftime("%Y-%m-%dT%H:%M:%SZ")
    digest = hashlib.sha256(canonical(args)).hexdigest()
    assert digest == PUBLIC_INPUT_SHA256

    print("REA P248 - UMA NOVA FERRAMENTA PENDENTE")
    print("Ferramenta:", TOOL)
    print("Dados: exemplo publico sintetico do REA original")
    print("SHA256 argumentos:", digest)
    print("Fonte SHA Git:", PUBLIC_SOURCE_GIT_BLOB)
    print("Validade ate (UTC):", expiry)
    print("ANTES: leitura cifrada completa das Evidence existentes")
    print("OPERACAO: cria/retém Evidence de certificacao sintetica")
    print("DEPOIS: nova leitura cifrada para provar preservacao de 6 Evidence")
    print("NAO abre/fecha binarios, nao abre GDB, nao toca em dispositivos.")
    print("A operacao positiva NO MCP permanente AINDA NAO ocorreu.")
    approved = input(
        "Escreve AUTORIZO_OPERACAO_SENSIVEL para esta operacao: "
    ).strip()
    if approved != APPROVAL:
        raise RuntimeError("Autorizacao recusada: nenhuma assinatura criada")
    authorization = {
        "tool": TOOL, "arguments_sha256": digest,
        "scope": "sensitive", "reason": REASON,
        "confirmed_by_owner": True, "acknowledgement": APPROVAL,
    }
    message = {
        "purpose": "REA_OWNER_APPROVAL_V1",
        "nonce": nonce, "expires_at": expiry, "step_index": 1,
        "tool": TOOL, "arguments_sha256": digest,
        "scope": "sensitive", "reason": REASON,
        "acknowledgement": APPROVAL,
    }
    with tempfile.TemporaryDirectory(prefix="rea-p248-runtime-",dir=directory) as d:
        message_path = Path(d)/"message.json"
        signature_path = Path(d)/"signature.bin"
        message_path.write_bytes(canonical(message))
        subprocess.run([
            "openssl","pkeyutl","-sign","-rawin","-inkey",str(private),
            "-in",str(message_path),"-out",str(signature_path)
        ],capture_output=True,check=True)
        verified = subprocess.run([
            "openssl","pkeyutl","-verify","-rawin","-pubin",
            "-inkey",str(public),"-in",str(message_path),
            "-sigfile",str(signature_path)
        ],capture_output=True,check=False)
        signature = signature_path.read_bytes()
        if verified.returncode != 0 or len(signature) != 64:
            raise RuntimeError("Assinatura Ed25519 invalida")
    authorization["owner_signature"] = base64.b64encode(signature).decode("ascii")
    body = {
        "protocol": 1, "nonce": nonce, "expires_at": expiry,
        "steps": [
            {"tool":"get_evidence_bundle",
             "arguments":{"detail":"complete"}},
            {"tool":TOOL, "arguments":args,"authorization":authorization},
            {"tool":"get_evidence_bundle",
             "arguments":{"detail":"complete"}},
        ],
    }
    path = Path.home()/("rea-p248-runtime-signed-"+nonce+".json")
    fd = os.open(path,os.O_WRONLY|os.O_EXCL|os.O_CREAT,0o600)
    with os.fdopen(fd,"wb") as f:
        f.write(canonical(body)+b"\n")
    print("REA_P248_OWNER_SIGNATURE=PASS_LOCAL_ONLY")
    print("FICHEIRO_TERMUX=", path)
    public_download=Path("/sdcard/Download")
    if public_download.is_dir() and os.access(public_download,os.W_OK):
        download=public_download/path.name
        try:
            fd = os.open(download,os.O_WRONLY|os.O_EXCL|os.O_CREAT,0o600)
            with os.fdopen(fd,"wb") as f:
                f.write(canonical(body)+b"\n")
            print("FICHEIRO_DOWNLOADS=",download)
        except OSError:
            print("FICHEIRO_DOWNLOADS=UNAVAILABLE")
    else:
        print("FICHEIRO_DOWNLOADS=UNAVAILABLE")
    print("FICHEIRO_ASSINADO_EXPIRA_UTC=",expiry)
    print("Envia ao chat apenas o ficheiro JSON assinado.")
    print("NUNCA envies os PEM, as chaves privadas ou passwords.")


if __name__ == "__main__":
    main()
