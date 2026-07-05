#!/usr/bin/env node
'use strict';
/**
 * TON - Tipbot Oracle Node
 * Watches the X filtered stream for @xrptipbot / @xahtipbot commands,
 * encodes them as 85-byte opinions and submits them (batched, <=16 per
 * Invoke, parameter names 0x00..0x0F) to the tip Hook on Xahau.
 *
 * deps: npm i node-fetch@2 xrpl-client xrpl-accountlib
 *
 * ~/.tipbotcfg (JSON):
 * {
 *   "bearer_token": "...",            // X API v2 bearer
 *   "seed": "s...",                   // family seed of THIS oracle's member account
 *   "wss": "wss://xahau.network"      // optional
 * }
 */

const fs = require('fs');
const crypto = require('crypto');
const fetch = require('node-fetch');
const { XrplClient } = require('xrpl-client');
const lib = require('xrpl-accountlib');

const cfgPath = '~/.tipbotcfg';

const RULE = '@xrptipbot OR @xahtipbot';
const HOOK_ACCOUNT = 'rtipboteEEZ6JkTNvcYgUZbiYyrV2W7DQ';
const NETWORK_ID = 21337;                 // Xahau mainnet
const DEFAULT_WSS = 'wss://xahau.network';
const SNID_TWITTER = 1;
const MAX_OPINIONS_PER_INVOKE = 16;       // hook processes params 0..F
const FLUSH_INTERVAL_MS = 8000;
const LLS_WINDOW = 20;                    // LastLedgerSequence = validated + this
const SEEN_CAP = 4096;                    // tweet-id dedupe LRU size

function log(level, message, data = null) {
  const timestamp = new Date().toISOString();
  let output = `[${timestamp}] [${level.toUpperCase()}] ${message}`;
  if (data !== null) {
    output += ` | ${typeof data === 'object' ? JSON.stringify(data, null, 2) : String(data)}`;
  }
  console.log(output);
}

function loadConfig() {
  try {
    if (!fs.existsSync(cfgPath))
      throw new Error(`Config file not found at ${cfgPath}`);
    const data = JSON.parse(fs.readFileSync(cfgPath, 'utf-8'));

    if (!data.bearer_token || typeof data.bearer_token !== 'string')
      throw new Error("please define 'bearer_token' in ~/.tipbotcfg (non-empty string)");
    if (!data.seed || typeof data.seed !== 'string')
      throw new Error("please define 'seed' in ~/.tipbotcfg (family seed of this oracle's member account)");

    log('INFO', 'Configuration loaded successfully');
    return {
      bearerToken: data.bearer_token,
      seed: data.seed,
      wss: data.wss || DEFAULT_WSS
    };
  } catch (error) {
    log('ERROR', 'Failed to load configuration', error.message);
    process.exit(1);
  }
}

/* ------------------------------------------------------------------ */
/* base58 (ripple alphabet) r-address -> 20 byte accid hex            */
/* ------------------------------------------------------------------ */

const B58 = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';
const B58_MAP = (() => {
  const m = Object.create(null);
  for (let i = 0; i < B58.length; i++) m[B58[i]] = BigInt(i);
  return m;
})();

function decodeAccountID(addr) {
  let num = 0n;
  for (const ch of addr) {
    const v = B58_MAP[ch];
    if (v === undefined) throw new Error(`invalid base58 character '${ch}' in ${addr}`);
    num = num * 58n + v;
  }
  let leading = 0;
  while (addr[leading] === B58[0]) leading++;

  let hex = num.toString(16);
  if (hex === '0') hex = '';
  if (hex.length % 2) hex = '0' + hex;

  const body = Buffer.concat([Buffer.alloc(leading), Buffer.from(hex, 'hex')]);
  if (body.length !== 25 || body[0] !== 0x00)
    throw new Error(`not an account address: ${addr}`);

  const payload = body.slice(0, 21);
  const checksum = body.slice(21);
  const h = crypto.createHash('sha256')
    .update(crypto.createHash('sha256').update(payload).digest())
    .digest();
  if (!h.slice(0, 4).equals(checksum))
    throw new Error(`bad address checksum: ${addr}`);

  return payload.slice(1).toString('hex').toUpperCase();
}

/* ------------------------------------------------------------------ */
/* tweet parsing                                                       */
/* ------------------------------------------------------------------ */

function parseTipbotTweet(tweet) {
  const text = tweet?.data?.text;
  const id   = tweet?.data?.id;      // keep as STRING: snowflakes exceed 2^53
  const INVALID = { type: 'invalid' };

  if (!text || !id) return INVALID;

  const ADDR = `r[${B58}]{24,33}`;
  const BOT  = `@(?:xrptipbot|xahtipbot)`;
  const AMT  = `(?<amount>\\d+(?:\\.\\d+)?)`;
  const CUR  = `(?<currency>[A-Fa-f0-9]{40}|[A-Za-z]{3})`;
  const ISS  = `(?::(?<issuer>${ADDR}))?`;

  let m;

  m = text.match(new RegExp(`${BOT}\\s+withdraw\\s+${AMT}\\s+${CUR}${ISS}\\s+to\\s+(?<dest>${ADDR})(?=\\s|$)`, `im`));
  if (m) return { type: 'withdraw', id, amount: parseFloat(m.groups.amount), currency: m.groups.currency.toUpperCase(), issuer: m.groups.issuer ?? null, dest: m.groups.dest };

  m = text.match(new RegExp(`@(?<recipient>[A-Za-z0-9_]{1,50})\\s+${BOT}\\s+\\+${AMT}(?:\\s+${CUR}${ISS})?(?=\\s|$)`, `im`));
  if (m) return { type: 'tip', id, amount: parseFloat(m.groups.amount), currency: (m.groups.currency ?? 'XAH').toUpperCase(), issuer: m.groups.issuer ?? null, recipient: m.groups.recipient };

  return INVALID;
}

function resolveRecipientId(tweet, username) {
  const users = tweet?.includes?.users ?? [];
  const uname = username.toLowerCase();
  const u = users.find(u => (u.username || '').toLowerCase() === uname);
  return u?.id ?? null; // string
}

/* ------------------------------------------------------------------ */
/* opinion codec (BigInt-safe for all u64 fields)                      */
/* ------------------------------------------------------------------ */

const makeOpinion = (
    social_network_id,   /* 0 - 255 */
    post_id,             /* u64: number (safe int) or BigInt */
    user_id_to,          /* u64 number/BigInt, or 40 hex chars of xahau accid */
    user_id_from,        /* u64: number (safe int) or BigInt */
    currency_code,       /* 0 for xah, or 40 hex chars of currency code */
    issuer_acc_id,       /* 0 for xah, or 40 hex chars of issuer accid */
    amount_tipped        /* positive JS float */
) =>
{
    const toU64 = (v, name) =>
    {
        if (typeof v === 'number')
        {
            if (!Number.isSafeInteger(v) || v < 0)
                throw new Error(name + " must be a safe non-negative integer (use BigInt for values > 2^53)");
            v = BigInt(v);
        }
        if (typeof v !== 'bigint' || v < 0n || v > 0xFFFFFFFFFFFFFFFFn)
            throw new Error(name + " must be a u64 (number or BigInt)");
        return v;
    };

    const checkHex = (hextocheck, hexsize, hexname) =>
    {
        if (typeof(hextocheck) != 'string' ||
            hextocheck.length != hexsize ||
            !/^[0-9a-fA-F]+$/.test(hextocheck))
            throw new Error(hexname + " must be a hex string of exactly " + hexsize + " characters");
    };

    const makeLEHex = (big, field_len_nibbles) =>
    {
        let tmp = big.toString(16);
        if (tmp.length % 2 == 1)
            tmp = '0' + tmp;
        tmp = tmp.toUpperCase();

        let fin = '';
        for (let i = tmp.length - 2; i >= 0; i -= 2)
            fin += tmp.slice(i, i + 2);

        return fin.padEnd(field_len_nibbles, '0');
    };

    const makeLEXFLHex = (num, field_len_nibbles) =>
    {
        const MIN_MANTISSA = 1000000000000000n;
        const MAX_MANTISSA = 9999999999999999n;
        const MIN_EXP = -96;
        const MAX_EXP = 80;

        function makeXfl(exp, man) {
            if (typeof exp !== 'bigint') exp = BigInt(exp);
            if (typeof man !== 'bigint') man = BigInt(man);
            if (man === 0n) return 0n;

            const neg = man < 0n;
            if (neg) man = -man;

            while (man > MAX_MANTISSA) { man /= 10n; exp++; }
            while (man < MIN_MANTISSA) { man *= 10n; exp--; }

            if (exp > MAX_EXP || exp < MIN_EXP) return -1n;

            let xfl = neg ? 0n : 1n;
            xfl = (xfl << 8n) | (BigInt(exp) + 97n);
            xfl = (xfl << 54n) | man;
            return xfl;
        }

        let d = String(parseFloat(String(num))).toLowerCase();
        let e = 0;
        let s = d.split('e');
        if (s.length === 2) { e = parseInt(s[1]); d = s[0]; }
        s = d.split('.');
        if (s.length === 2) { d = d.replace('.', ''); e -= s[1].length; }

        const xfl = makeXfl(e, d);
        if (xfl < 0n) throw new Error(`Cannot encode ${num} as XFL`);

        const be = xfl.toString(16).padStart(16, '0');
        let le = '';
        for (let i = 14; i >= 0; i -= 2) le += be.slice(i, i + 2);

        if (field_len_nibbles % 2 !== 0) throw new Error('field_len_nibbles must be even');
        if (field_len_nibbles < 16) throw new Error('field_len_nibbles must be >= 16 (XFL is 8 bytes)');
        return le.padEnd(field_len_nibbles, '0').toUpperCase();
    };

    if (typeof(social_network_id) != 'number' ||
        social_network_id < 0 || social_network_id > 255 ||
        Math.floor(social_network_id) != social_network_id)
        throw new Error("social_network_id must be an integer between 0 and 255");

    post_id = toU64(post_id, "post_id");

    if (typeof(user_id_to) == 'string')
        checkHex(user_id_to, 40, "user_id_to");
    else
        user_id_to = toU64(user_id_to, "user_id_to");

    user_id_from = toU64(user_id_from, "user_id_from");

    if (typeof(currency_code) == 'string')
        checkHex(currency_code, 40, "currency_code");
    else if (typeof(currency_code) != 'number' || currency_code != 0)
        throw new Error("currency_code must be either 0 or a 20 byte currency code in HEX");

    if (typeof(issuer_acc_id) == 'string')
        checkHex(issuer_acc_id, 40, "issuer_acc_id");
    else if (typeof(issuer_acc_id) != 'number' || issuer_acc_id != 0)
        throw new Error("issuer_acc_id must be either 0 or a 20 byte account id in HEX");

    if (typeof(amount_tipped) != 'number' || !(amount_tipped > 0))
        throw new Error("amount_tipped must be a positive number");

    // execution to here means inputs are well formed

    let out = '';

    out += makeLEHex(BigInt(social_network_id), 2);
    out += makeLEHex(post_id, 16);
    if (typeof(user_id_to) == 'string')
        out += user_id_to.toUpperCase();
    else
    {
        out += '0'.repeat(24);
        out += makeLEHex(user_id_to, 16);
    }

    out += makeLEHex(user_id_from, 16);
    out += (currency_code == 0 ? '0'.repeat(40) : currency_code.toUpperCase());
    out += (issuer_acc_id == 0 ? '0'.repeat(40) : issuer_acc_id.toUpperCase());
    out += makeLEXFLHex(amount_tipped, 16);

    if (out.length !== 170)
        throw new Error(`internal error: opinion is ${out.length} nibbles, expected 170`);

    return out;
};

// 3-char code -> standard 160-bit currency layout (ascii at bytes 12..14),
// 40-hex passes through, XAH -> 0
function currencyField(cur) {
  if (cur === 'XAH') return 0;
  if (/^[A-Fa-f0-9]{40}$/.test(cur)) return cur.toUpperCase();
  if (/^[A-Za-z]{3}$/.test(cur)) {
    const buf = Buffer.alloc(20);
    buf.write(cur.toUpperCase(), 12, 'ascii');
    return buf.toString('hex').toUpperCase();
  }
  throw new Error(`unsupported currency: ${cur}`);
}

// parsed tweet + author id -> 170-nibble opinion hex
function opinionFromParsed(parsed, authorId) {
  const cur = currencyField(parsed.currency);
  const iss = parsed.issuer ? decodeAccountID(parsed.issuer) : 0;

  if (cur !== 0 && iss === 0)
    throw new Error('issued currency requires an issuer (cur:issuer)');
  if (cur === 0 && iss !== 0)
    throw new Error('XAH cannot have an issuer');

  let to;
  if (parsed.type === 'withdraw')
    to = decodeAccountID(parsed.dest);
  else
    to = BigInt(parsed.recipientId);

  return makeOpinion(
    SNID_TWITTER,
    BigInt(parsed.id),
    to,
    BigInt(authorId),
    cur,
    iss,
    parsed.amount
  );
}

/* ------------------------------------------------------------------ */
/* xahau submission                                                    */
/* ------------------------------------------------------------------ */

class XahauSubmitter {
  constructor(wss, seed) {
    this.wss = wss;
    this.account = lib.derive.familySeed(seed);
    this.client = new XrplClient(wss);
    this.definitions = null;
    this.sequence = null;
  }

  async init() {
    await this.client.ready();
    log('INFO', `Connected to ${this.wss} as ${this.account.address}`);

    // pull live definitions from the node so Invoke/HookParameters
    // always serialize against what the network actually runs
    const defs = await this.client.send({ command: 'server_definitions' });
    if (defs.error) throw new Error(`server_definitions: ${defs.error_message || defs.error}`);
    this.definitions = new lib.XrplDefinitions(defs);

    await this.syncSequence();
  }

  async syncSequence() {
    const ai = await this.client.send({
      command: 'account_info',
      account: this.account.address,
      ledger_index: 'current'
    });
    if (ai.error) throw new Error(`account_info: ${ai.error_message || ai.error}`);
    this.sequence = ai.account_data.Sequence;
    log('INFO', `Account sequence synced: ${this.sequence}`);
  }

  async currentValidatedLedger() {
    const r = await this.client.send({ command: 'ledger', ledger_index: 'validated' });
    return r?.ledger_index ?? r?.ledger?.ledger_index;
  }

  // sign once at Fee:'0', ask the node what the hook execution actually
  // costs, then re-sign with the real fee
  async estimateFee(tx) {
    const probe = { ...tx, Fee: '0' };
    const { signedTransaction } = lib.sign(probe, this.account, this.definitions);
    const feeResp = await this.client.send({ command: 'fee', tx_blob: signedTransaction });
    const base = BigInt(feeResp?.drops?.base_fee ?? '1000');
    return ((base * 12n) / 10n).toString(); // 20% headroom
  }

  async submitOpinions(opinions /* array of 170-hex strings, <=16 */) {
    if (opinions.length === 0) return;
    if (opinions.length > MAX_OPINIONS_PER_INVOKE)
      throw new Error('too many opinions for one Invoke');

    if (this.sequence === null) await this.syncSequence();

    const validated = await this.currentValidatedLedger();
    const lls = validated + LLS_WINDOW;

    const tx = {
      TransactionType: 'Invoke',
      Account: this.account.address,
      Destination: HOOK_ACCOUNT,
      NetworkID: NETWORK_ID,
      Sequence: this.sequence,
      LastLedgerSequence: lls,
      Fee: '0',
      HookParameters: opinions.map((hex, i) => ({
        HookParameter: {
          HookParameterName: i.toString(16).toUpperCase().padStart(2, '0'),
          HookParameterValue: hex
        }
      }))
    };

    tx.Fee = await this.estimateFee(tx);

    const { signedTransaction, id } = lib.sign(tx, this.account, this.definitions);

    log('INFO', `Submitting Invoke seq=${tx.Sequence} fee=${tx.Fee} opinions=${opinions.length} hash=${id}`);

    const res = await this.client.send({ command: 'submit', tx_blob: signedTransaction });
    const er = res?.engine_result ?? res?.error ?? 'unknown';

    if (er === 'tesSUCCESS' || er === 'terQUEUED') {
      this.sequence++;
      log('SUCCESS', `Submitted (${er})`, { hash: id });
      // fire and forget: report hook results once validated
      this.reportHookResults(id, lls).catch(e =>
        log('WARN', 'Result tracking failed', e.message));
      return;
    }

    // sequence drift: resync and let caller retry
    if (er === 'tefPAST_SEQ' || er === 'terPRE_SEQ' || er === 'tefALREADY') {
      log('WARN', `Sequence issue (${er}), resyncing`);
      await this.syncSequence();
      throw new Error(`retryable: ${er}`);
    }

    // tec results consume the sequence and a fee
    if (typeof er === 'string' && er.startsWith('tec')) {
      this.sequence++;
      throw new Error(`claimed fee, not applied: ${er}`);
    }

    throw new Error(`submit failed: ${er} ${res?.engine_result_message ?? ''}`);
  }

  // poll until validated (or LLS passes), then decode HookReturnString
  async reportHookResults(hash, lls) {
    for (;;) {
      await new Promise(r => setTimeout(r, 3000));

      const r = await this.client.send({ command: 'tx', transaction: hash });

      if (r?.validated) {
        const result = r.meta?.TransactionResult;
        const execs = r.meta?.HookExecutions ?? [];
        for (const e of execs) {
          const he = e.HookExecution;
          if (!he) continue;
          const msg = he.HookReturnString
            ? Buffer.from(he.HookReturnString, 'hex').toString('utf8')
            : '(no return string)';
          log('HOOK', `${result} rc=${he.HookReturnCode}`, msg);
        }
        if (execs.length === 0)
          log('HOOK', `Validated ${result}, no hook executions`);
        return;
      }

      const validated = await this.currentValidatedLedger();
      if (validated > lls) {
        log('WARN', `Txn ${hash} not found after LastLedgerSequence ${lls} - dropped`);
        return;
      }
    }
  }
}

/* ------------------------------------------------------------------ */
/* opinion queue                                                       */
/* ------------------------------------------------------------------ */

const opinionQueue = [];
let flushing = false;
let submitter = null;

function enqueueOpinion(hex, context) {
  opinionQueue.push(hex);
  log('QUEUE', `Opinion queued (${opinionQueue.length} pending)`, context);
  if (opinionQueue.length >= MAX_OPINIONS_PER_INVOKE)
    flushOpinions(); // don't wait for the timer when a full batch is ready
}

async function flushOpinions() {
  if (flushing || opinionQueue.length === 0 || !submitter) return;
  flushing = true;

  try {
    while (opinionQueue.length > 0) {
      const batch = opinionQueue.splice(0, MAX_OPINIONS_PER_INVOKE);
      try {
        await submitter.submitOpinions(batch);
      } catch (e) {
        if (String(e.message).startsWith('retryable')) {
          opinionQueue.unshift(...batch); // put back, retry next tick
          log('WARN', 'Batch requeued', e.message);
        } else {
          log('ERROR', `Batch of ${batch.length} opinions dropped`, e.message);
        }
        break;
      }
    }
  } finally {
    flushing = false;
  }
}

/* ------------------------------------------------------------------ */
/* twitter stream                                                      */
/* ------------------------------------------------------------------ */

const CONFIG = loadConfig();

const seenIds = new Set();
function alreadySeen(id) {
  if (seenIds.has(id)) return true;
  seenIds.add(id);
  if (seenIds.size > SEEN_CAP) {
    // drop oldest (Set iterates in insertion order)
    const first = seenIds.values().next().value;
    seenIds.delete(first);
  }
  return false;
}

function handleTweet(tweet) {
  const id = tweet?.data?.id;
  if (!id || alreadySeen(id)) return;

  const parsed = parseTipbotTweet(tweet);
  if (parsed.type === 'invalid') {
    log('DEBUG', 'Tweet matched rule but no valid command', { id });
    return;
  }

  const authorId = tweet?.data?.author_id;
  if (!authorId) {
    log('WARN', 'No author_id on tweet (missing tweet.fields?)', { id });
    return;
  }

  try {
    if (parsed.type === 'tip') {
      const recipientId = resolveRecipientId(tweet, parsed.recipient);
      if (!recipientId) {
        log('WARN', `Could not resolve @${parsed.recipient} to a user id (missing expansions?)`, { id });
        return;
      }
      parsed.recipientId = recipientId;
    }

    const hex = opinionFromParsed(parsed, authorId);
    enqueueOpinion(hex, {
      id,
      type: parsed.type,
      amount: parsed.amount,
      currency: parsed.currency,
      to: parsed.type === 'withdraw' ? parsed.dest : `@${parsed.recipient}`
    });
  } catch (e) {
    log('WARN', `Skipping tweet ${id}`, e.message);
  }
}

async function addRule() {
  log('INFO', `Adding rule: "${RULE}"`);

  const response = await fetch('https://api.x.com/2/tweets/search/stream/rules', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${CONFIG.bearerToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ add: [{ value: RULE }] })
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`HTTP ${response.status} - ${errorText}`);
  }

  const result = await response.json();
  log('SUCCESS', 'Rule added (or already existed)', result);
  return result;
}

async function connectStream(retryCount = 0) {
  const MAX_RETRIES = 12;
  const BASE_DELAY_MS = 5000;

  // author_id gives us user_id_from; the mention expansion resolves the
  // tip recipient's numeric user id from their @username
  const streamUrl = 'https://api.x.com/2/tweets/search/stream'
    + '?tweet.fields=author_id,entities'
    + '&expansions=author_id,entities.mentions.username'
    + '&user.fields=id,username';

  try {
    log('INFO', `Connecting to streaming endpoint (attempt ${retryCount + 1}/${MAX_RETRIES + 1})`);

    const response = await fetch(streamUrl, {
      headers: { Authorization: `Bearer ${CONFIG.bearerToken}` }
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorText}`);
    }

    log('SUCCESS', 'Stream connected (live only) - waiting for data');

    const decoder = new TextDecoder();
    let buffer = '';

    for await (const chunk of response.body) {
      buffer += decoder.decode(chunk, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.length === 0) continue; // keep-alive

        retryCount = 0; // healthy stream: reset backoff

        try {
          const tweet = JSON.parse(trimmed);

          if (tweet.data) {
            log('TWEET', 'Matching tweet received', {
              id: tweet.data.id,
              author_id: tweet.data.author_id,
              text_preview: tweet.data.text?.substring(0, 120) + (tweet.data.text?.length > 120 ? '...' : '')
            });
            handleTweet(tweet);
          } else if (tweet.errors) {
            log('ERROR', 'Error payload from stream', tweet.errors);
          } else {
            log('DEBUG', 'Non-tweet message received', tweet);
          }
        } catch (parseErr) {
          log('WARN', 'Failed to parse JSON line', {
            linePreview: trimmed.substring(0, 200),
            error: parseErr.message
          });
        }
      }
    }

    // server closed the stream cleanly: reconnect rather than exit
    log('WARN', 'Stream closed by server - reconnecting');
    await new Promise(r => setTimeout(r, BASE_DELAY_MS));
    return connectStream(0);
  } catch (error) {
    log('ERROR', 'Stream error occurred', error.message);

    if (retryCount < MAX_RETRIES) {
      let delay = Math.min(BASE_DELAY_MS * Math.pow(2, retryCount), 90000);

      if (error.message.includes('429') || error.message.includes('TooManyConnections')) {
        delay = 30000 + (retryCount * 15000);
        log('WARN', `TooManyConnections detected - using extended ${delay / 1000}s backoff`);
      }

      log('INFO', `Reconnecting in ${delay / 1000} seconds...`);
      await new Promise(resolve => setTimeout(resolve, delay));
      return connectStream(retryCount + 1);
    } else {
      log('FATAL', 'Maximum reconnection attempts reached');
      process.exit(1);
    }
  }
}

/* ------------------------------------------------------------------ */

process.on('SIGINT', () => {
  log('INFO', 'Received SIGINT - shutting down gracefully');
  process.exit(0);
});
process.on('SIGTERM', () => {
  log('INFO', 'Received SIGTERM - shutting down gracefully');
  process.exit(0);
});

async function main() {
  try {
    submitter = new XahauSubmitter(CONFIG.wss, CONFIG.seed);
    await submitter.init();

    setInterval(flushOpinions, FLUSH_INTERVAL_MS);

    await addRule();
    await connectStream();
  } catch (error) {
    log('FATAL', 'Application failed to start', error.message);
    process.exit(1);
  }
}

main();
