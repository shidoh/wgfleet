// app.js — the dashboard's only required script.
//
// lockAction(form): gates an action form (confirm), then locks its submit button
// so a slow ZT link can't be double-submitted. Moved verbatim from the old inline
// <script> in layout.html. The topology connector lines are rendered server-side
// (inline SVG in the flexbox connector column), and the collapsibles are native
// <details>; keepDetailsOpen (below) only stops a poll from closing one that is open.
// The page is fully usable without any of it.

// lockAction gates an action form, then locks its submit button so a slow ZT
// link can't be double-submitted. confirm() (from the form's data-confirm) runs
// FIRST and short-circuits on cancel; only once it passes do we let the native
// submit proceed and disable the button on the next tick (a disabled button
// won't submit, so we must disable AFTER submission has started).
function lockAction(form) {
  var msg = form.getAttribute('data-confirm');
  if (msg && !window.confirm(msg)) return false;
  // Tell the server this was confirmed HERE, so it does not ask again on its own
  // page. That page is the floor: this function is deferred, so before it parses —
  // and always, with JavaScript off — the onsubmit handler either throws or never
  // runs, and the form submits with no prompt at all. A confirmation that can
  // vanish without notice is not one, so the server keeps its own.
  var f = form.querySelector('input[name="confirm"]');
  if (f) f.value = '1';
  var btn = form.querySelector('button[type="submit"], button:not([type])');
  if (btn) {
    var pending = btn.getAttribute('data-pending') || 'Working…';
    setTimeout(function () { btn.disabled = true; btn.textContent = pending; }, 0);
  }
  return true; // allow native submit
}

// openTargetCard: when the page is landed on with a #client-<id> anchor — which is
// where issuing a credential now redirects — open that card's hand-out.
//
// The highlight is CSS (:target), but a <details> cannot be opened by a selector,
// and the whole point of landing on the card is that what you came for is inside
// it. Without this the operator arrives at the right card and still has to click.
window.addEventListener('DOMContentLoaded', function () {
  var id = window.location.hash;
  if (!id || id.indexOf('#client-') !== 0) return;
  var card = document.querySelector(id);
  if (!card) return;
  var d = card.querySelector('details.hand-out');
  if (d) d.open = true;
  card.scrollIntoView({ block: 'center' });
});

// markSection: highlight the header section the current page belongs to. By path,
// not by page title: confirmation pages are POST responses under /devices/… and
// belong to Devices even though their titles say "Delete device".
window.addEventListener('DOMContentLoaded', function () {
  var section = window.location.pathname.indexOf('/devices') === 0 ? 'devices'
    : (window.location.pathname === '/' || window.location.pathname.indexOf('/nodes') === 0 ? 'nodes' : '');
  if (!section) return;
  var link = document.querySelector('.mainnav-link[data-section="' + section + '"]');
  if (link) link.setAttribute('aria-current', 'page');
});

// keepDetailsOpen: carry the open/closed state of a <details id="…"> across an htmx
// poll swap.
//
// A polled fragment is re-rendered from scratch, and the server only knows its own
// default for `open` — so a panel the operator opened to read snapped shut on the
// next poll (the rollout panel: every 15 s idle, and at once when a run ended, which
// is the moment its per-node errors are worth reading). Only elements with an id
// are tracked: without one there is nothing to match the new node to the old.
(function () {
  var remembered = {};
  document.addEventListener('htmx:beforeSwap', function (e) {
    remembered = {};
    var open = e.detail.target.querySelectorAll('details[id]');
    for (var i = 0; i < open.length; i++) remembered[open[i].id] = open[i].open;
  });
  document.addEventListener('htmx:afterSwap', function (e) {
    var fresh = e.detail.target.querySelectorAll('details[id]');
    for (var i = 0; i < fresh.length; i++) {
      if (fresh[i].id in remembered) fresh[i].open = remembered[fresh[i].id];
    }
  });
})();
