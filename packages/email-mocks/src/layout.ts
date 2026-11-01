/**
 * Folding of a `DKIM-Signature` value the way each signer writes it: which
 * tags share a line, the continuation indent, and where long values break.
 * Folding is whitespace inside the field, so it does not change what
 * relaxed canonicalization signs (RFC 6376 section 3.4.2), but it is what a
 * parser reading the raw header sees. Each layout returns the text after
 * the field name's colon; with an empty `b=` it ends in `b=`.
 */
import type { SignatureLayout, Tag } from './dkim.js';

export type WrapRule =
  /** Break before a `:` once a line would pass `width` columns. */
  | { at: 'before-colon'; width: number; indent: string }
  /** Break after a `:` once a line would pass `width` columns. */
  | { at: 'after-colon'; width: number; indent: string }
  /** Fill each line to `width` columns, breaking anywhere. */
  | { at: 'width'; width: number; indent: string }
  /** Cut `name=value` into pieces of `size` characters. */
  | { at: 'chunk'; size: number; indent: string };

export interface LineStyle {
  /** Whitespace between the field name's colon and the first tag. */
  lead: string;
  /** Tag names that share a physical line; any other tag gets its own line. */
  lines: string[][];
  /** Indent of each line after the first. */
  indent: string;
  wrap?: Partial<Record<string, WrapRule>>;
}

/** `name=value` folded per `rule`, starting at `column` (a TAB counts as one). */
function wrapValue(name: string, value: string, column: number, rule: WrapRule, suffix = ''): string {
  const prefix = `${name}=`;
  if (rule.at === 'chunk') {
    const all = prefix + value;
    const pieces: string[] = [];
    for (let i = 0; i < all.length; i += rule.size) pieces.push(all.slice(i, i + rule.size));
    return pieces.join(`\r\n${rule.indent}`);
  }
  if (rule.at === 'width') {
    let out = prefix;
    let rest = value;
    let room = rule.width - column - prefix.length;
    while (rest.length > room && room > 0) {
      out += `${rest.slice(0, room)}\r\n${rule.indent}`;
      rest = rest.slice(room);
      room = rule.width - rule.indent.length;
    }
    return out + rest;
  }
  const items = value.split(':');
  let out = prefix;
  let col = column + prefix.length;
  items.forEach((item, i) => {
    const last = i === items.length - 1;
    const piece = rule.at === 'before-colon' ? (i === 0 ? item : `:${item}`) : last ? item : `${item}:`;
    // The `;` that follows the value counts against the width of its line.
    const room = piece.length + (last ? suffix.length : 0);
    if (i > 0 && col + room > rule.width) {
      out += `\r\n${rule.indent}`;
      col = rule.indent.length;
    }
    out += piece;
    col += piece.length;
  });
  return out;
}

/** Tags grouped onto lines; `;` after every tag but the last, one space between tags on a line. */
export function lineLayout(style: LineStyle, fieldName = 'DKIM-Signature'): SignatureLayout {
  const group = new Map<string, number>();
  style.lines.forEach((names, i) => names.forEach((n) => group.set(n, i)));
  return (tags: Tag[]) => {
    const lines: string[] = [];
    let current = '';
    let currentGroup: number | undefined;
    tags.forEach(([name, value], i) => {
      const g = group.get(name) ?? -1 - i;
      if (current !== '' && g !== currentGroup) {
        lines.push(current);
        current = '';
      }
      const start = lines.length === 0 ? fieldName.length + 1 + style.lead.length : style.indent.length;
      const column = start + current.length + (current === '' ? 0 : 1);
      const rule = style.wrap?.[name];
      const semi = i === tags.length - 1 ? '' : ';';
      const text = rule && value !== '' ? wrapValue(name, value, column, rule, semi) : `${name}=${value}`;
      current += (current === '' ? '' : ' ') + text + semi;
      currentGroup = g;
    });
    lines.push(current);
    return style.lead + lines.join(`\r\n${style.indent}`);
  };
}

/** Every tag on one unfolded line (iCloud, Yahoo). */
export function singleLine(): SignatureLayout {
  return (tags) => ` ${tags.map(([n, v]) => `${n}=${v}`).join('; ')}`;
}

/**
 * Exchange Online: the tags before `h=` packed onto lines of at most
 * `width` characters, then `h=`, `bh=` and `b=` each on one unbroken line;
 * one-space indent.
 */
export function exchangeLayout(width = 78, fieldName = 'DKIM-Signature'): SignatureLayout {
  return (tags) => {
    const lines: string[] = [];
    let current = '';
    let packing = true;
    tags.forEach(([name, value], i) => {
      const text = `${name}=${value}${i === tags.length - 1 ? '' : ';'}`;
      if (name === 'h') packing = false;
      const start = lines.length === 0 ? fieldName.length + 2 : 1;
      if (current !== '' && (!packing || start + current.length + 1 + text.length > width)) {
        lines.push(current);
        current = '';
      }
      current += (current === '' ? '' : ' ') + text;
      if (!packing) {
        lines.push(current);
        current = '';
      }
    });
    if (current !== '') lines.push(current);
    return ` ${lines.join('\r\n ')}`;
  };
}

/**
 * Proton and GMX/WEB.DE: TAB-indented lines, `h=` broken after a `:` and
 * `b=` filled to a fixed width, both continued with TAB SP. `optional`
 * tags join the previous line when it stays within `width`, else take
 * their own.
 */
export function tabLayout(opts: {
  lines: string[][];
  hWidth: number;
  bWidth: number;
  optional?: { tag: string; width: number };
}): SignatureLayout {
  const base = lineLayout({
    lead: ' ',
    indent: '\t',
    lines: opts.lines,
    wrap: {
      h: { at: 'after-colon', width: opts.hWidth, indent: '\t ' },
      b: { at: 'width', width: opts.bWidth, indent: '\t ' },
    },
  });
  if (!opts.optional) return base;
  const { tag, width } = opts.optional;
  return (tags) => {
    const out = base(tags);
    const lines = out.split('\r\n');
    const at = lines.findIndex((l) => l.startsWith(`\t${tag}=`));
    if (at > 0 && lines[at - 1]!.length + lines[at]!.length <= width) {
      lines.splice(at - 1, 2, `${lines[at - 1]} ${lines[at]!.slice(1)}`);
    }
    return lines.join('\r\n');
  };
}

/**
 * Perl Mail::DKIM's signer (version 1.20240923). Before signing,
 * `prettify` wraps every tag but `b=` (Mail::DKIM::KeyValueList::wrap with
 * Mail::DKIM::TextWrap): margin 72, a TAB advancing to the next multiple
 * of 8, separator CRLF TAB, a break allowed before each tag name, `h=`
 * broken before `:`, `bh=` anywhere, other values at whitespace. After
 * signing, `prettify_safe` keeps that text as it is, appends `; b=` with no
 * break check, and fills the signature data to the margin.
 */
export function mailDkimLayout(fieldName = 'DKIM-Signature'): SignatureLayout {
  return (tags) => {
    const [, b] = tags[tags.length - 1]!;
    const pretty = new TextWrap(fieldName.length + 1);
    tags.slice(0, -1).forEach(([name, value], i) => {
      pretty.breakAfter = undefined;
      pretty.breakBefore = undefined;
      if (i > 0) pretty.add(';');
      pretty.flush();
      pretty.add(` ${name}=`);
      pretty.flush();
      if (name === 'bh') {
        pretty.breakAfter = /./s;
      } else if (name === 'h') {
        pretty.breakAfter = /\s/;
        pretty.breakBefore = /:/;
      } else {
        pretty.breakAfter = /\s/;
      }
      pretty.add(value);
    });
    pretty.flush();
    const unsigned = `${pretty.out}; b=`;
    if (b === '') return unsigned;
    const safe = new TextWrap(fieldName.length + 1);
    safe.add(unsigned);
    safe.flush();
    safe.breakAfter = /./s;
    safe.add(b);
    safe.flush();
    return safe.out;
  };
}

class TextWrap {
  out = '';
  breakAfter?: RegExp;
  breakBefore?: RegExp;
  private swallow: RegExp | undefined = /\s/;
  private noBuffering = false;
  private mayBreak = false;
  private softSpace = '';
  private word = '';
  private readonly margin = 72;
  private readonly separator = '\r\n\t';

  constructor(private cur: number) {}

  private static column(cur: number, text: string): number {
    let c = cur;
    for (const ch of text) {
      if (ch === '\t') c = (Math.floor(c / 8) + 1) * 8;
      else if (ch === '\r' || ch === '\n') c = 0;
      else c += 1;
    }
    return c;
  }

  add(text: string): void {
    this.word += text;
    while (this.word.length > 0) {
      let word: string;
      const before = this.breakBefore && new RegExp(`^([\\s\\S]+?)(${this.breakBefore.source})`).exec(this.word);
      const after = !before && this.breakAfter && new RegExp(`^([\\s\\S]*?)(${this.breakAfter.source})`).exec(this.word);
      if (before) {
        word = before[1]!;
        this.word = this.word.slice(word.length);
      } else if (after) {
        word = after[1]! + after[2]!;
        this.word = this.word.slice(after[0].length);
      } else if (this.noBuffering) {
        word = this.word;
        this.word = '';
      } else {
        break;
      }
      let next = '';
      const sw = this.swallow && new RegExp(`(${this.swallow.source})$`).exec(word);
      if (sw) {
        next = sw[1]!;
        word = word.slice(0, -next.length);
      }
      const toPrint = this.softSpace + word;
      const pos = TextWrap.column(this.cur, toPrint);
      if (pos > this.margin && this.mayBreak) {
        const afterSep = TextWrap.column(this.cur, this.separator);
        if (afterSep < this.cur) {
          this.out += this.separator;
          this.softSpace = '';
          this.cur = afterSep;
          this.word = word + next + this.word;
          continue;
        }
      }
      this.out += toPrint;
      this.softSpace = next;
      this.cur = pos;
      this.mayBreak = true;
    }
  }

  flush(): void {
    const [nb, sw] = [this.noBuffering, this.swallow];
    this.noBuffering = true;
    this.swallow = undefined;
    this.add('');
    [this.noBuffering, this.swallow] = [nb, sw];
  }
}
