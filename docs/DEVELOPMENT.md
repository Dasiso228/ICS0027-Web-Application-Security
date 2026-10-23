# Local HTTPS development

Use Python 3.11+ on Linux. The guide targets Arch Linux and fish; virtualenv activation is not required.

```sh
sudo pacman -Syu --needed python python-pip git mkcert nss
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip check
```

Run the following as your ordinary user. `mkcert -install` installs a local development CA into the available trust stores and may request privilege elevation. Open Firefox at least once before this step, then restart the browser after installing the CA.

```sh
mkdir -p certs
chmod 700 certs
mkcert -install
mkcert -cert-file certs/localhost.pem -key-file certs/localhost-key.pem localhost 127.0.0.1
chmod 600 certs/localhost-key.pem
```

Keep the certificate files, database and the mkcert CA private key out of Git. Each reviewer generates their own local certificates; do not distribute yours.

Start the server from the repository root:

```sh
.venv/bin/python -m flask --app app --no-debug run --host 127.0.0.1 --port 5443 --cert certs/localhost.pem --key certs/localhost-key.pem --no-debugger --no-reload
```

Open <https://localhost:5443/>. Use this hostname consistently. Stop with Ctrl+C. After changing Python code, stop and start the server again. Debugging and automatic reloading stay disabled.

In another fish terminal, check the certificate and response:

```fish
set webpm_ca (mkcert -CAROOT)
curl --cacert "$webpm_ca/rootCA.pem" https://localhost:5443/health
curl --cacert "$webpm_ca/rootCA.pem" -I https://localhost:5443/
```

Do not enter credentials through a certificate warning. If Firefox does not trust the certificate, close it, run `mkcert -install` again after a Firefox profile exists, and reopen it. Check that the URL is `https://localhost:5443/` and the certificate covers `localhost`.

Checkpoint 2 uses one Flask development-server process with TLS directly. The Nginx/Gunicorn deployment in the Checkpoint 1 plan remains future deployment work. This development setup has no HTTP listener or public binding; the finished application also rejects non-HTTPS requests. It does not trust forwarded headers. Multiple workers would require a different session design.

The database is created automatically as `instance/vault.sqlite3`. The directory is mode 700 and the file is mode 600. Sessions and keys live in process memory, so stopping the server logs everyone out while the encrypted database remains.

Measure the planned KDF settings on the actual development machine:

```sh
.venv/bin/python -m tools.benchmark_kdf
```

The script uses generated test input and prints timing/version information only. Keep the configured KDF parameters stable for existing accounts.

Sources: [mkcert](https://github.com/FiloSottile/mkcert), [Arch package](https://archlinux.org/packages/extra/x86_64/mkcert/), [Flask development server](https://flask.palletsprojects.com/en/stable/server/).
