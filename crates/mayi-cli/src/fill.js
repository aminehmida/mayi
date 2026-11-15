// Runs in an isolated world of the page's main frame: it shares the page's
// DOM but not its JavaScript, so page scripts can neither see these
// functions nor replace the built-ins they call. It never reads or returns
// a field's value, only where the sign-in fields are.
(() => {
  if (globalThis.mayiFill) return;

  const TEXTUAL = ['text', 'email', 'tel', ''];
  const CODE_TYPES = ['text', 'tel', 'number', 'password', ''];
  let fields = {};

  const type = (el) => (el.getAttribute('type') || '').toLowerCase();
  const autocomplete = (el) => (el.getAttribute('autocomplete') || '').toLowerCase().split(/\s+/);
  const labels = (el) => {
    try {
      return [...(el.labels || [])].map((l) => l.textContent).join(' ');
    } catch {
      return '';
    }
  };
  const hint = (el) =>
    [el.name, el.id, el.getAttribute('placeholder'), el.getAttribute('aria-label'), labels(el)]
      .join(' ')
      .toLowerCase();

  // Shown, enabled, editable, and not parked off-screen (a common way to hide
  // a decoy field from people but not from fillers).
  const usable = (el) => {
    if (!el.isConnected || el.disabled || el.readOnly) return false;
    const style = getComputedStyle(el);
    if (style.display === 'none' || style.visibility !== 'visible') return false;
    const r = el.getBoundingClientRect();
    return r.width > 1 && r.height > 1 && r.right > 0 && r.bottom + scrollY > 0;
  };

  // Every input of the document, including inside open shadow roots.
  const inputs = (root = document, out = []) => {
    for (const el of root.querySelectorAll('*')) {
      if (el.tagName === 'INPUT') out.push(el);
      if (el.shadowRoot) inputs(el.shadowRoot, out);
    }
    return out;
  };

  const select = (css) => {
    try {
      return document.querySelector(css);
    } catch {
      return null;
    }
  };

  const isCode = (el) => {
    if (!CODE_TYPES.includes(type(el)) || type(el) === 'password') return false;
    if (autocomplete(el).includes('one-time-code')) return true;
    return /one[-_ ]?time|otp|totp|2fa|mfa|two[-_ ]?factor|verification|verify|security[-_ ]?code|auth[a-z]*[-_ ]?code|passcode|\bcode\b/.test(
      hint(el),
    );
  };

  const isIdentifier = (el) => {
    const t = type(el);
    if (!TEXTUAL.includes(t)) return false;
    const ac = autocomplete(el);
    if (ac.includes('username') || ac.includes('email') || t === 'email') return true;
    return /user|login|e-?mail|account|identifier|phone|handle|\bid\b/.test(hint(el));
  };

  const deepActive = () => {
    let el = document.activeElement;
    while (el && el.shadowRoot && el.shadowRoot.activeElement) el = el.shadowRoot.activeElement;
    return el;
  };

  const fail = (error) => ({ ok: false, error });

  // Words on the button that submits a sign-in form, in a few languages.
  const SUBMIT_WORDS =
    /^(sign ?in|log ?in|submit|continue|next|verify|confirm|go|done|anmelden|einloggen|weiter|se connecter|connexion|continuer|suivant|valider|iniciar sesi[oó]n|entrar|continuar|siguiente|accedi|avanti|inloggen|doorgaan|volgende|ログイン|次へ|登录|下一步)\b/i;

  const center = (el) => {
    el.scrollIntoView({ block: 'center', inline: 'nearest' });
    const r = el.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return null;
    return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
  };

  // Every element matching `css`, including inside open shadow roots.
  const deepAll = (css, root = document, out = []) => {
    for (const el of root.querySelectorAll('*')) {
      if (el.matches(css)) out.push(el);
      if (el.shadowRoot) deepAll(css, el.shadowRoot, out);
    }
    return out;
  };

  const buttonUsable = (el) => {
    if (!el.isConnected || el.disabled) return false;
    const style = getComputedStyle(el);
    if (style.display === 'none' || style.visibility !== 'visible') return false;
    const r = el.getBoundingClientRect();
    return r.width > 1 && r.height > 1;
  };

  globalThis.mayiFill = {
    // Finds the fields this page asks for. `opts` holds optional CSS
    // selectors for pages where the guess is wrong.
    find(opts) {
      fields = {};
      const all = inputs().filter(usable);

      if (opts.code) {
        const el = select(opts.code);
        if (!el || !usable(el)) return fail(`no usable field matches ${opts.code}`);
        fields.code = [el];
      } else {
        // One box per digit: four to eight one-character fields.
        const boxes = all.filter((el) => el.maxLength === 1 && CODE_TYPES.includes(type(el)));
        if (boxes.length >= 4 && boxes.length <= 8) {
          fields.code = boxes;
        } else {
          const codes = all.filter(isCode);
          if (codes.length === 1) fields.code = codes;
        }
      }
      const inCode = new Set(fields.code || []);

      const passwords = all.filter((el) => type(el) === 'password' && !inCode.has(el));
      // A second password field means a sign-up or password change form,
      // where a filled-in current password lets someone set a new one.
      if (passwords.length > 1) {
        return fail(
          `this page has ${passwords.length} password fields, so it looks like a sign-up or ` +
            'password change form. Mayi only fills sign-in forms.',
        );
      }
      if (opts.password) {
        const el = select(opts.password);
        if (!el || !usable(el) || type(el) !== 'password') {
          return fail(`${opts.password} does not name a usable password field`);
        }
        fields.password = [el];
      } else if (passwords.length === 1) {
        fields.password = passwords;
      }

      if (opts.username) {
        const el = select(opts.username);
        if (!el || !usable(el) || !TEXTUAL.includes(type(el))) {
          return fail(`${opts.username} does not name a usable text or email field`);
        }
        fields.username = [el];
      } else if (fields.password) {
        // The identifier field just before the password, preferring one
        // that says what it is.
        const pw = fields.password[0];
        const before = all.filter(
          (el) =>
            !inCode.has(el) &&
            TEXTUAL.includes(type(el)) &&
            el.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING,
        );
        const named = before.filter(isIdentifier);
        const last = before[before.length - 1];
        const pick = named.length ? named[named.length - 1] : last && last.form === pw.form ? last : null;
        if (pick) fields.username = [pick];
      } else if (!fields.code) {
        // A page that asks for the identifier first, on its own.
        const named = all.filter(isIdentifier);
        if (named.length === 1) fields.username = named;
      }

      return {
        ok: true,
        username: !!fields.username,
        password: !!fields.password,
        code: fields.code ? fields.code.length : 0,
      };
    },

    // Focuses a found field and selects what is in it, so typing replaces
    // it. Returns "ok", or why it cannot be typed into.
    focus(name, index) {
      const el = (fields[name] || [])[index || 0];
      if (!el || !el.isConnected) return 'the field is gone from the page';
      if (name === 'password' && type(el) !== 'password') return 'the field is no longer a password field';
      if (!usable(el)) return 'the field is hidden or disabled now';
      el.scrollIntoView({ block: 'center', inline: 'nearest' });
      el.focus();
      if (deepActive() !== el) return 'the page moved the focus away';
      if (el.value) {
        try {
          el.select();
        } catch {}
      }
      return 'ok';
    },

    // Whether the field now holds `length` characters, without reading them.
    holds(name, index, length) {
      const el = (fields[name] || [])[index || 0];
      return !!el && el.isConnected && el.value.length === length;
    },

    // Whether what was typed is still in a field anyone can see.
    lingers(name, length) {
      return (fields[name] || []).some((el) => usable(el) && el.value.length === length);
    },

    // Empties the fields, telling the page as typing would.
    clear(name) {
      for (const el of fields[name] || []) {
        if (!el.isConnected || !el.value) continue;
        el.value = '';
        el.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      }
      return true;
    },

    // The centre of a visible element, in the viewport, for a mouse click.
    point(css) {
      const el = select(css);
      return el && el.isConnected ? center(el) : null;
    },

    // How to submit after typing into the field `name`: Enter, when the
    // browser would submit the form on Enter; otherwise a click on the
    // sign-in button after the field, if there is one.
    submitter(name, index) {
      const field = (fields[name] || [])[index || 0];
      if (!field || !field.isConnected) return { how: 'enter' };
      const form = field.form;
      if (form) {
        const elements = [...form.elements];
        const hasSubmit = elements.some(
          (el) => (el.type === 'submit' || el.type === 'image') && !el.disabled,
        );
        const blocking = elements.filter(
          (el) => el.tagName === 'INPUT' && !['hidden', 'submit', 'image', 'button', 'reset', 'checkbox', 'radio', 'file'].includes(type(el)),
        );
        if (hasSubmit || blocking.length <= 1) return { how: 'enter' };
      }
      const label = (el) => (el.innerText || el.value || el.getAttribute('aria-label') || '').trim();
      const button = deepAll('button, input[type=submit], input[type=button], [role=button]')
        .filter((el) => buttonUsable(el) && field.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING)
        .find((el) => SUBMIT_WORDS.test(label(el)));
      const point = button && center(button);
      if (!point) return { how: 'enter' };
      return { how: 'click', label: label(button).slice(0, 40), x: point.x, y: point.y };
    },

    forget() {
      fields = {};
    },
  };
})();
