'use strict';
/* Pan and zoom, shared by the three canvases (Topology, the Map and the Files map) so they move the same way: scroll or drag the
   background to pan, Ctrl+scroll or pinch to zoom about the pointer, Shift+scroll to pan sideways, and − + 0 F from the keyboard.
   However many wheel or pointer events arrive in a frame, the view is drawn once in it, and it is saved only when it settles.
   Each view keeps its own { x, y, k } object: this changes that object in place, so whatever else reads it sees the same view.
   Loaded after kernel.js and before the views. DOM APIs only. */

/* box: the element that takes the events. opt:
     view      the view object to move (changed in place)
     apply(v)  draws v: a transform on the world, a zoom label. Called at most once a frame
     min, max  the zoom range
     ignore    a selector inside box whose wheel and presses are its own (a toolbar, a legend that scrolls)
     pannable(target, ev)  whether a press there drags the view; the middle button always does
     moved()   the person moved the view (not a fit or a reveal)
     tap(ev)   a press on the background that did not move
     panStart()  the drag has started moving
     settled(v)  the view has been still for a moment: save it here */
function sfCanvas(box, opt) {
  const o = { min: 0.2, max: 2.5, step: 1.2, ignore: null, pannable: () => true, ...opt };
  const c = { view: o.view || { x: 0, y: 0, k: 1 }, panning: false };
  let frame = 0, settle = 0, quietUntil = 0, drag = null;
  const pointers = new Map();                    // touch and pen pointers down on the background: two of them pinch
  const draw = () => { frame = 0; o.apply(c.view); };
  const clamp = (k) => Math.max(o.min, Math.min(o.max, k));

  /* draw on the next frame, or now: a caller that measures right after (a fit before a reveal) asks for now */
  c.apply = (now = false) => {
    if (now) { cancelAnimationFrame(frame); draw(); } else if (!frame) frame = requestAnimationFrame(draw);
    if (o.settled) { clearTimeout(settle); settle = setTimeout(() => o.settled(c.view), 300); }
  };
  c.set = (v, now) => { Object.assign(c.view, v); c.apply(now); };
  c.zoomAt = (k, cx, cy, now = false) => {
    const v = c.view, f = clamp(k) / v.k;
    c.set({ x: cx - (cx - v.x) * f, y: cy - (cy - v.y) * f, k: v.k * f }, now);
  };
  c.zoomTo = (k) => c.zoomAt(k, box.clientWidth / 2, box.clientHeight / 2, true);      // a button or a key: one step, drawn now
  c.zoomBy = (f) => c.zoomTo(c.view.k * f);
  c.panBy = (dx, dy) => c.set({ x: c.view.x + dx, y: c.view.y + dy });
  /* bounds in world units on screen: as large as fits up to `most`, no smaller than `least`, centred where it is smaller than the box
     (or at the top left, with centre: false, for a canvas whose corners hold controls) */
  c.fit = (b, { most = 1, least = o.min, left = 24, top = 24, right = 24, bottom = 24, centre = true } = {}) => {
    const W = box.clientWidth, H = box.clientHeight, w = Math.max(1, b.x2 - b.x1), h = Math.max(1, b.y2 - b.y1);
    if (!W || !H) return false;
    const k = Math.max(least, Math.min(most, o.max, (W - left - right) / w, (H - top - bottom) / h));
    const x = centre ? Math.max(left, (W - w * k) / 2) : left, y = centre ? Math.max(top, (H - h * k) / 2) : top;
    c.set({ k, x: x - b.x1 * k, y: y - b.y1 * k }, true);
    return true;
  };
  /* a world point to the middle of the box, zoomed in to at least `k` */
  c.centerOn = (x, y, k = c.view.k) => c.set({ k: clamp(k), x: box.clientWidth / 2 - x * clamp(k), y: box.clientHeight / 2 - y * clamp(k) }, true);
  c.quiet = () => Date.now() < quietUntil;       // the click that ends a drag is not a click
  /* the zoom keys, for a view's own keydown handler: true when the key was one of them */
  c.key = (ev, fit) => {
    if (ev.ctrlKey || ev.metaKey || ev.altKey) return false;
    const act = { '+': () => c.zoomBy(o.step), '=': () => c.zoomBy(o.step), '-': () => c.zoomBy(1 / o.step), 0: () => c.zoomTo(1), f: fit, F: fit }[ev.key];
    if (!act) return false;
    ev.preventDefault(); act(); o.moved?.();
    return true;
  };

  const inside = (ev) => !!(o.ignore && ev.target.closest?.(o.ignore));
  box.addEventListener('wheel', (ev) => {
    if (inside(ev)) return;
    ev.preventDefault();
    const px = ev.deltaMode === 1 ? 16 : ev.deltaMode === 2 ? box.clientHeight : 1;
    if (ev.ctrlKey || ev.metaKey) {                // a trackpad pinch arrives as Ctrl+wheel
      const r = box.getBoundingClientRect();
      c.zoomAt(c.view.k * Math.exp(-ev.deltaY * px * 0.0025), ev.clientX - r.left, ev.clientY - r.top);
    } else if (ev.shiftKey && !ev.deltaX) c.panBy(-ev.deltaY * px, 0);
    else c.panBy(-ev.deltaX * px, -ev.deltaY * px);
    o.moved?.();
  }, { passive: false });

  const pinch = () => {
    const [a, b] = [...pointers.values()];
    return { d: Math.hypot(a.x - b.x, a.y - b.y) || 1, x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
  };
  box.addEventListener('pointerdown', (ev) => {
    if (inside(ev) || (ev.button !== 0 && ev.button !== 1)) return;
    if (ev.button === 0 && !o.pannable(ev.target.nodeType === 1 ? ev.target : ev.target.parentElement, ev)) return;
    if (ev.button === 1) ev.preventDefault();      // no autoscroll
    if (ev.pointerType !== 'mouse') pointers.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
    if (pointers.size === 2) { const r = box.getBoundingClientRect(), p = pinch(); drag = { pinch: p, k: c.view.k, r, moved: true }; return; }
    drag = { id: ev.pointerId, sx: ev.clientX, sy: ev.clientY, vx: c.view.x, vy: c.view.y, moved: false };
  });
  box.addEventListener('pointermove', (ev) => {
    if (!drag) return;
    if (pointers.has(ev.pointerId)) pointers.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
    if (drag.pinch) {
      if (pointers.size < 2) return;
      const p = pinch(), r = drag.r;
      c.zoomAt(drag.k * p.d / drag.pinch.d, p.x - r.left, p.y - r.top);
      return;
    }
    if (ev.pointerId !== drag.id) return;
    const dx = ev.clientX - drag.sx, dy = ev.clientY - drag.sy;
    if (!drag.moved) {
      if (Math.abs(dx) + Math.abs(dy) < 4) return;
      drag.moved = true; c.panning = true;
      box.setPointerCapture?.(drag.id); box.classList.add('panning');
      o.panStart?.();
    }
    c.set({ x: drag.vx + dx, y: drag.vy + dy });
    o.moved?.();
  });
  const end = (ev) => {
    pointers.delete(ev.pointerId);
    if (!drag || (!drag.pinch && ev.pointerId !== drag.id)) return;
    if (drag.pinch && pointers.size) return;        // one finger still down: the pinch ends when both are up
    const was = drag;
    drag = null; c.panning = false;
    box.classList.remove('panning');
    if (was.moved) quietUntil = Date.now() + 250;
    else if (ev.type === 'pointerup' && ev.button === 0) o.tap?.(ev);
  };
  box.addEventListener('pointerup', end);
  box.addEventListener('pointercancel', end);
  return c;
}
