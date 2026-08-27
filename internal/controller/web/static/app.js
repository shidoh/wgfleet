// app.js — the dashboard's only required script.
//
// lockAction(form): gates an action form (confirm), then locks its submit button
// so a slow ZT link can't be double-submitted. Moved verbatim from the old inline
// <script> in layout.html. The topology connector lines are rendered server-side
// (inline SVG in the flexbox connector column), and the collapsibles are native
// <details>, so no other JS is needed — the page is fully usable without it.

// lockAction gates an action form, then locks its submit button so a slow ZT
// link can't be double-submitted. confirm() (from the form's data-confirm) runs
// FIRST and short-circuits on cancel; only once it passes do we let the native
// submit proceed and disable the button on the next tick (a disabled button
// won't submit, so we must disable AFTER submission has started).
function lockAction(form) {
  var msg = form.getAttribute('data-confirm');
  if (msg && !window.confirm(msg)) return false;
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
