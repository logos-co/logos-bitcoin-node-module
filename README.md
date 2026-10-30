# logos-bitcoin-node-module

`bitcoin_node_module`: the sources a Bitcoin wallet uses, per network. It keeps each
network's source list and one Tor setting (the Tor that comes with Logos, or your own SOCKS
proxy), answers a route table per role, keeps a book of Kyoto's
peers, and probes every enabled server's health with address-free calls. It holds no keys and
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
| `rpc` | `https://host[:port][/path]`, or `http://` for onion services and your network | chain, locally scanned history and pending, fees, broadcast |
| `local` | `logos://bitcoind_module` (id `local`, stage 2) | chain, history, pending, fees, broadcast |

- `history` means the source is asked about the wallet's addresses. Electrum and Esplora only; RPC never receives wallet addresses. Every reply
  that changes sources carries `exposes`, the enabled sources that learn the addresses.
- `tor` is per source and on by default. Turning it off is refused for an onion service. A
  source reached without Tor by choice is listed in `withoutTor`.
- A server on your own network is reached directly: loopback, private, CGNAT, link-local and
  IPv6 unique-local addresses, and `.local`, `.lan`, `.home.arpa` and `.internal` names that
  resolve only to such addresses. The rules are the Zcash node module's `net/client.rs`.
- Without a Tor route (below), a source routed through Tor has no route. It never falls back
  to a direct connection.
- Operators, not hosts, count: a user-added server defaults to its registered domain
  (`you` on your network), unless the caller names one.
- An Esplora or RPC server may take HTTP basic auth (`https://user:pw@host/api`, or `credentials`).
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

`init_defaults` fills what is absent, field by field: the proxy `tor` (below), and per network Kyoto on, one server for fee rates only (history off), and every other source
off. Sources are switched on one by one. PublicNode RPC is disabled and direct by default.
Existing mainnet configurations gain this disabled catalog entry on load, preserving existing
settings and avoiding a duplicate when the endpoint was already added manually.

| Network | Fee server (on) | Off, ready to switch on |
|---|---|---|
| mainnet | Blockstream Esplora, onion | PublicNode Bitcoin Core RPC (direct), blockstream.info, both mempool.space addresses, Blockstream Electrum (TLS and onion) |
| signet | Blockstream Esplora, onion | blockstream.info, both mempool.space addresses |
| testnet4 | an Electrum onion service (Fulcrum, plain tcp over Tor) | stagemole.eu and c3-soft.com Electrum (TLS) |
| regtest | none | only your own sources |

Chosen by checking live on 2026-10-10, each request on a fresh Tor circuit. Blockstream's
onion answered 8 of 8 on mainnet and signet; mempool.space's onion accepted every connection
and closed it unanswered (0 of 8), its clearnet API answered 2 to 5 of 8 through Tor and timed
out directly from our network, and blockstream.info through Tor was rate-limited once (HTTP
429). An onion service needs no exit relay, which can be blocked or watch the traffic.
The onion addresses come from each operator: the `Onion-Location` headers of blockstream.info
and mempool.space, and Blockstream's own Electrum `server.features`.

Testnet4 was checked on 2026-10-11, three probes per server on fresh circuits. No Esplora
answered over Tor: mempool.space's API and its Electrum on 40002 timed out (0 of 3), its onion
closed every connection unanswered, and Blockstream serves no testnet4. Of the seven servers in
Electrum's own testnet4 list (electrum/chains/testnet4/servers.json), three answered 3 of 3 and
ship: the onion service on its tcp port, and stagemole.eu and c3-soft.com, whose certificates the
web PKI trusts. The other four answer only with self-signed certificates (two of them version 1);
pin one with `certSha256` to use it.

## Tor

`set_proxy` takes `tor`, a `socks5h://host:port` URL of your own Tor, or an empty string (no
proxy). `tor` is the Tor
that comes with Logos: tor_module (logos-tor-module), reached through the SOCKS port its
`status()` names. While `tor` is set, a follower asks `status()` every 2 s until Tor is ready,
then every 30 s; that call also starts Tor. Routes and probes use that port, and change when it
does. A store from before (version 1) whose proxy was the old default, `socks5h://127.0.0.1:9050`,
moves to `tor` once; a proxy someone chose stays. Older builds set a version 2 store aside as
unreadable.

Without a route through Tor, `unrouted` says why: no proxy is set, the built-in Tor is starting,
its SOCKS port is off (the Tor app turns it on), or it is not available. `source_health` carries
`tor`: `{ state, progress, detail, socks }` for the built-in Tor, null for your own.

## Routes

`route_table(network)` gives one list per role, each `{ id, kind, url, operator, route }` with
`route` `tor`, `direct` or `onion`, in failover order:

- `chain`: the local node, then one enabled RPC endpoint, then Kyoto; only when neither is on, every Electrum server (the
  most-work chain wins). It follows what is switched on, so an unreachable Kyoto never hands
  the chain to a server.
- `history`: the local node, RPC and Kyoto, which learn no address, then servers with history on.
- `pending`: the local node and RPC, then servers with history on.
- `fees`: the local node and RPC, every indexed server, then Kyoto.
- `broadcast`: the local node, then one enabled RPC endpoint, then Kyoto; only when neither is on, the history servers.
- `check`: every Electrum/Esplora server, asked for tips and headers only.

RPC probes check the genesis hash, tip and block-filter availability. Only one RPC endpoint may
be enabled per network. RPC credentials use the same restricted storage and read API as Esplora.

Plus `proxy` (the SOCKS URL to dial; for `tor`, tor_module's port), `peers` (Kyoto's peers,
below), `crossCheck` (two operators among chain and check) and `unrouted` (enabled sources left
out, and why: no Tor route, suspect, wrong network). A disabled source is never routed. Entries carry `certSha256` when the source has a
pin, and `userAdded` for a server the person added: the wallet core speaks plain text only to
such a server on the person's network.

## Kyoto's peers

The curated list per network is `rust-lib/peer-lists/<network>.json`, written at release time
by the crawler (logos-bitcoin-peer-list, `peer-list release`): format 1, a `version`, when it
was signed (`created`), the day of its last run (`date`), a note, onion v3 peers as
`host:port`, a key id, and an Ed25519 signature over `logos-bitcoin-peer-list/1\n` followed by
the list as compact JSON in field order with `signature` null (`refreshUrl` stays in the format,
null). A list is used only if its signature checks against a key compiled into this build
(`rust-lib/keys/`): today that is the crawler's **TEST key**, and the release key is not chosen
yet. A shipped list that fails is replaced by an empty one that says why. The shipped lists are
**provisional**: each note says how many runs it comes from. Nothing is fetched: a newer list
comes with a newer build.

Each install keeps its own book per network, `kyoto_peers_<network>.json` in the persistence
directory (atomic, owner-only): entries `{ addr, port, services, source: list|learned|seed,
from?, firstSeen, lastSeen, lastOk, okCount, failStreak, skipUntil }`, services and Unix times
as decimal strings, `lastOk` and `skipUntil` null when unset. The shipped list seeds it as
`list`; a peer that a newer build's list drops stays as learned (`from: "list"`) if it worked
here in the last 30 days, and leaves the book otherwise. At most 2,000 entries, and 64 learned
from any one `from`. A learned peer that never worked is dropped after 7 days, and any learned
peer without a success in 30 days.

- `report_peers(network, reportJson)`, wallet core only: `{ outcomes: [{ peer, ok, reason? }],
  learned: [{ addr, port, services, seenAt, from }] }`, at most 500 of each. Success sets
  `lastOk`, counts and clears the streak; the third failure in a row skips the peer for 24 h.
  A learned peer is kept if it is onion v3 (on regtest, on your network), serves bits 0, 3 and
  6, and was seen within 3 days.
- `route_table(network).peers`: `[{ peer, source, ok }]`, `ok` if it ever worked, most recent
  success first, then list before learned. Skipped peers are left out unless every peer is
  skipped. Your own peers (`set_own_peers`) replace the book, as `source: "own"`. Kyoto has one
  connection type for every peer, so your network's peers and peers through Tor don't mix, and
  an onion peer needs Tor.
- `peer_list(network)`: the signed list, own peers, `usable` (as `peers`) and `counts: { list,
  learned, seed, usable, okLast30d }`.

Bitcoin Core 31.1's fixed seeds, onion v3 only, ship as `peer-lists/seeds-<network>.json`
(`peer-list seeds` from Core's `contrib/seeds`) and enter the book as `seed`; they never go to
Kyoto. When fewer than 12 usable peers worked in the last 30 days, the health thread asks up to
8 seeds over Tor (version handshake, `sendaddrv2`, one `getaddr`) and keeps what they gossip by
the rules above, as learned with `from` the seed: a day after a harvest a seed answered, an hour
after one none answered (at most 3 tries a day), and only while a wallet is open on that
network, with Kyoto on, no own peers and a proxy. On regtest, `regtest.json` may name loopback
or LAN seeds, reached directly: `{ "harvestSeeds": ["127.0.0.1:18444"] }`.

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

`bitcoin_wallet_backend` may change sources, the proxy and own peers, clear suspects, and say
a wallet is open (`set_wallet_open`), which locks that network's
settings and the proxy until it closes. The backend and `bitcoin_wallet_core_module` may read
routes and report a mismatch, which marks a source suspect until the backend clears it. Only
the wallet core reads credentials and reports on Kyoto's peers. Reads are open. `callers.json` in the persistence directory
widens the gate for tests. Events: `source_health_changed`, `routes_changed`, `source_suspect`.
u64 values cross as decimal strings. Persists `bitcoin_sources.json` and the peer books,
atomically, owner-only.

```bash
cd rust-lib && cargo test --no-default-features
BITCOIN_TEST_TOR=socks5h://127.0.0.1:9050 cargo test --no-default-features --test live -- --ignored --nocapture
# The harvest against a regtest bitcoind it starts itself (31.x), its address book filled first
BITCOIND=/path/to/bitcoind cargo test --no-default-features --test regtest -- --ignored harvest_against --nocapture
```

## Windows

`packages.x86_64-windows.*` cross-build from x86_64-linux; the portable `.lgx` passes
nix-bundle-lgx's system-DLL gate, and the plugin exports only `qt_plugin_instance` and
`qt_plugin_query_metadata_v2`. Under logosctl on Windows 10.0.26200 (2026-10-11):
`init_defaults`, the signed mainnet peer list verified, the route tables, a server of your own on
the LAN (`tcp://framework.lan:…`) routed directly and probed in 108 ms, a public host in plain
text refused, and an unload in 96 ms.
