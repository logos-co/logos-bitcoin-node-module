# logos-bitcoin-node-module

`bitcoin_node_module`: the sources a Bitcoin wallet uses, per network. It keeps each
network's source list and one Tor proxy, answers a route table per role, keeps Kyoto's peer
lists, and probes every enabled server's health with address-free calls. It holds no keys and
carries no wallet traffic.

Networks: `mainnet`, `testnet4`, `signet`, and `regtest` when the instance persistence
directory holds `regtest.json` (any JSON object; test harnesses only).

## Sources

Each source is `{ id, kind, url, operator, label, use, history, tor, certSha256? }`; `lan` and
the route are computed. Kinds:

| Kind | url | Fills |
|---|---|---|
| `kyoto` | `p2p://peer-list` (id `kyoto`) | chain, history (through block filters), fees (block averages), broadcast |
| `electrum` | `ssl://host:port` (50002), or `tcp://host:port` (50001) for onion services and your network | history and pending when `history` is on, fees, check, and the chain when Kyoto and the local node are off |
| `esplora` | `https://host[:port][/path]`, or `http://` for onion services and your network | history and pending when `history` is on, fees, check |
| `local` | `logos://bitcoind_module` (id `local`, stage 2) | chain, history, pending, fees, broadcast |

- `history` means the source is asked about the wallet's addresses. Servers only. Every reply
  that changes sources carries `exposes`, the enabled sources that learn the addresses.
- `tor` is per source and on by default. Turning it off is refused for an onion service. A
  source reached without Tor by choice is listed in `withoutTor`.
- A server on your own network is reached directly: loopback, private, CGNAT, link-local and
  IPv6 unique-local addresses, and `.local`, `.lan`, `.home.arpa` and `.internal` names that
  resolve only to such addresses. The rules are the Zcash node module's `net/client.rs`.
- Without a proxy, a source routed through Tor has no route. It never falls back to a direct
  connection.
- Operators, not hosts, count: a user-added server defaults to its registered domain
  (`you` on your network), unless the caller names one.
- An Esplora server may take HTTP basic auth (`https://user:pw@host/api`, or `credentials`).
  No read returns it; `get_sources` says `hasCredentials`, and only the wallet core reads it,
  with `source_credentials`. A list sent back without credentials keeps the stored ones.
- Plain `tcp://` or `http://` is only for an onion service or a server on your network, as in
  the wallet core; for a public host it is refused with `invalid parameters: …`.
- `certSha256` pins a TLS server's certificate (`ssl://` or `https://`): the SHA-256 of its
  end-entity certificate's DER, as the wallet core computes it, stored as 64 lowercase hex
  characters (colons accepted). It replaces the CAs and the name check; the handshake signature
  is still checked against that certificate's key. Set or cleared (null) with `set_source` or
  in `set_sources`, where an entry without it keeps the stored pin. The wallet core uses it
  for `ssl://` Electrum servers.

## Defaults

`init_defaults` fills what is absent, field by field: the proxy `socks5h://127.0.0.1:9050`,
and per network Kyoto on, one Esplora server for fee rates only (history off), and every other
source off. There are no presets; sources are switched on one by one.

| Network | Fee server (on) | Off, ready to switch on |
|---|---|---|
| mainnet | Blockstream Esplora, onion | blockstream.info, both mempool.space addresses, Blockstream Electrum (TLS and onion) |
| signet | Blockstream Esplora, onion | blockstream.info, both mempool.space addresses |
| testnet4 | mempool.space | mempool.space's onion |
| regtest | none | only your own sources |

Chosen by checking live on 2026-10-10, each request on a fresh Tor circuit. Blockstream's
onion answered 8 of 8 on mainnet and signet; mempool.space's onion accepted every connection
and closed it unanswered (0 of 8), its clearnet API answered 2 to 5 of 8 through Tor and timed
out directly from our network, and blockstream.info through Tor was rate-limited once (HTTP
429). An onion service needs no exit relay, which can be blocked or watch the traffic.
Blockstream serves no testnet4, so testnet4's only candidate is mempool.space, degraded on that
day. The onion addresses come from each operator: the `Onion-Location` headers of
blockstream.info and mempool.space, and Blockstream's own Electrum `server.features`.

## Routes

`route_table(network)` gives one list per role, each `{ id, kind, url, operator, route }` with
`route` `tor`, `direct` or `onion`, in failover order:

- `chain`: the local node, then Kyoto; only when neither is on, every Electrum server (the
  most-work chain wins). It follows what is switched on, so an unreachable Kyoto never hands
  the chain to a server.
- `history`: the local node and Kyoto, which learn no address, then servers with history on.
- `pending`: the local node, then servers with history on.
- `fees`: the local node, every server, then Kyoto.
- `broadcast`: the local node, then Kyoto; only when neither is on, the history servers.
- `check`: every server, asked for tips and headers only.

Plus `proxy`, `peers` (every peer Kyoto's route can use), `crossCheck` (two operators among
chain and check) and `unrouted` (enabled sources left out, and why: no proxy, suspect, wrong
network). A disabled source is never routed. Entries carry `certSha256` when the source has a
pin, and `userAdded` for a server the person added: the wallet core speaks plain text only to
such a server on the person's network.

## Kyoto's peers

The curated list per network is `rust-lib/peer-lists/<network>.json`, written by the crawler
(logos-bitcoin-peer-list): format 1, a `version`, when it was signed (`created`), the day of
its last run (`date`), a refresh URL, onion v3 peers as `host:port`, a key id, and an Ed25519
signature over `logos-bitcoin-peer-list/1\n` followed by the list as compact JSON in field
order with `signature` null. A list is used only if its signature checks against a key compiled
into this build (`rust-lib/keys/`): today that is the crawler's **TEST key**, and the release
key is not chosen yet. A shipped list that fails is replaced by an empty one that says why.

The shipped mainnet and signet lists are **provisional**: each list's note says how many runs
it comes from, fewer than the plan's 6 of 7 days. Testnet4 has no list yet; it will point at
our own nodes. Your own peers (`set_own_peers`) replace the list. Kyoto has one connection type
for every peer, so your network's peers and peers through Tor don't mix, and an onion peer needs
Tor. `route_table` lists every usable peer; the wallet core draws 8 at random per start and
skips a peer that keeps failing. `refresh_peer_list` fetches a newer list through the proxy and
keeps it only if it is for this network, has a higher version and its signature checks. A kept
list is checked again whenever the module starts, and is used only while it is newer than the
one this build ships.

## Health

The health thread probes every enabled server once a minute, four at a time, on one Tor
circuit per server: Electrum `server.version`, `server.features` (the genesis block) and
`blockchain.headers.subscribe`; Esplora `/blocks/tip/height`, `/blocks/tip/hash`, and
`/block-height/0` once per circuit. A server on another network is never routed. `probe`
asks now and answers within 15 s. A TLS server's row carries `certificate`: `{ certSha256,
subject, issuer, notBefore, notAfter, trusted }`, read in a handshake that proves the server
holds the key. An untrusted one (a self-signed server, or a pin that no longer matches) is
still shown, so the app can ask "Trust this certificate?" and pin it with `set_source`. Kyoto and the local node are not probed here: Kyoto reports
its peers today, and `local_node` asks bitcoind_module (logos-bitcoind-module) for its
`status()`: an optional dependency, so without it `local_node` answers that it is not loaded.

## Callers

`bitcoin_wallet_backend` may change sources, the proxy and own peers, clear suspects, refresh
the peer list, and say a wallet is open (`set_wallet_open`), which locks that network's
settings and the proxy until it closes. The backend and `bitcoin_wallet_core_module` may read
routes and report a mismatch, which marks a source suspect until the backend clears it. Only
the wallet core reads credentials. Reads are open. `callers.json` in the persistence directory
widens the gate for tests. Events: `source_health_changed`, `routes_changed`, `source_suspect`.
u64 values cross as decimal strings. Persists `bitcoin_sources.json`, atomically, owner-only.

```bash
cd rust-lib && cargo test --no-default-features
BITCOIN_TEST_TOR=socks5h://127.0.0.1:9050 cargo test --no-default-features --test live -- --ignored --nocapture
```
