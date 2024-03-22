# Vmessy
a messy implementation of vmess protocol for educational purposes.

## Usage
```bash
$ xray --config ./config/config.json
$ cargo run -- --config ./config/config.toml
```

run xray:
```bash
$ xray --config ./config/config.json
```

if you set `aead = false` in [`config.toml`](./config/config.toml) you might need to disable aead:
```bash
$ env "xray.vmess.aead.forced=false" xray --config ./config/config.json
```

or simply using docker-compose:
```bash
$ docker-compose up
```

and proxy your requests:
```bash
$ curl google.com --proxy http://127.0.0.1:1090
```
