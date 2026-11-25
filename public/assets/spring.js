// Apple WWDC "Designing Fluid Interfaces" Physics Engine (zero-dependency)
// Supports critically-damped & under-damped springs, velocity handoff, momentum projection, and rubber-banding.

export function prefersReducedMotion() {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

// Apple's exponential-decay momentum projection (decelerationRate = 0.998)
export function projectMomentum(initialVelocityPxPerSec, decelerationRate = 0.998) {
  return ((initialVelocityPxPerSec / 1000) * decelerationRate) / (1 - decelerationRate);
}

// Apple-style progressive rubber-band resistance past boundaries
export function rubberband(overshoot, dimension, constant = 0.55) {
  return (overshoot * dimension * constant) / (dimension + constant * Math.abs(overshoot));
}

// Interruptible spring driven by dampingRatio (1.0 = critically damped) and response (seconds)
export class SpringValue {
  constructor(initial = 0, { dampingRatio = 1.0, response = 0.32 } = {}) {
    this.value = initial;
    this.target = initial;
    this.velocity = 0;
    this.dampingRatio = dampingRatio;
    this.response = response;
    this.rafId = null;
    this.lastTs = null;
    this.onUpdate = null;
    this.onRest = null;
  }

  animateTo(target, { velocity = null, onUpdate = null, onRest = null } = {}) {
    this.target = target;
    if (velocity !== null) {
      this.velocity = velocity;
    }
    if (onUpdate) this.onUpdate = onUpdate;
    if (onRest) this.onRest = onRest;

    if (prefersReducedMotion()) {
      this.stop();
      this.value = target;
      this.velocity = 0;
      if (this.onUpdate) this.onUpdate(this.value);
      if (this.onRest) this.onRest();
      return;
    }

    if (this.rafId !== null) return; // Seamlessly retargets from live value & velocity!
    this.lastTs = performance.now();

    const step = (ts) => {
      const dt = Math.min((ts - this.lastTs) / 1000, 0.032); // Clamp dt for tab switch safety
      this.lastTs = ts;

      const omega = (2 * Math.PI) / this.response;
      const stiffness = omega * omega;
      const damping = 2 * this.dampingRatio * omega;

      const displacement = this.value - this.target;
      const acceleration = -stiffness * displacement - damping * this.velocity;

      this.velocity += acceleration * dt;
      this.value += this.velocity * dt;

      if (this.onUpdate) this.onUpdate(this.value);

      if (Math.abs(this.velocity) < 0.35 && Math.abs(this.value - this.target) < 0.35) {
        this.value = this.target;
        this.velocity = 0;
        this.rafId = null;
        if (this.onUpdate) this.onUpdate(this.value);
        if (this.onRest) this.onRest();
        return;
      }

      this.rafId = requestAnimationFrame(step);
    };

    this.rafId = requestAnimationFrame(step);
  }

  setImmediate(val) {
    this.stop();
    this.value = val;
    this.target = val;
    this.velocity = 0;
    if (this.onUpdate) this.onUpdate(val);
  }

  stop() {
    if (this.rafId !== null) {
      cancelAnimationFrame(this.rafId);
      this.rafId = null;
    }
  }
}

// Spring-animated segmented control thumb
export function bindSegmentedThumb(container) {
  if (!container) return { sync: () => {} };
  const thumb = container.querySelector('.segmented-thumb');
  const springX = new SpringValue(0, { dampingRatio: 1.0, response: 0.28 });
  const springW = new SpringValue(0, { dampingRatio: 1.0, response: 0.28 });

  const render = () => {
    thumb.style.transform = `translateX(${springX.value}px)`;
    thumb.style.width = `${springW.value}px`;
  };

  function sync(immediate = false) {
    const active = container.querySelector('.segmented-btn.is-active');
    if (!active || !thumb) return;
    const x = active.offsetLeft - 3;
    const w = active.offsetWidth;
    if (w === 0) return;

    if (immediate) {
      springX.setImmediate(x);
      springW.setImmediate(w);
      render();
    } else {
      springX.animateTo(x, { onUpdate: render });
      springW.animateTo(w, { onUpdate: render });
    }
  }

  window.addEventListener('resize', () => sync(true));
  return { sync };
}

// Interruptible, drag-to-dismiss Apple Sheet with 1:1 pointer tracking + momentum projection
export function createInteractiveSheet(backdrop, panel, dragHandle) {
  const springY = new SpringValue(40, { dampingRatio: 0.92, response: 0.32 });
  let isOpen = false;
  let onCloseCallback = null;
  let dragging = false;
  let startY = 0;
  let startOffset = 0;
  let samples = [];

  const applyTransform = (y) => {
    panel.style.transform = `translateY(${y}px)`;
  };

  function open({ onClose } = {}) {
    isOpen = true;
    onCloseCallback = onClose || null;
    backdrop.hidden = false;
    requestAnimationFrame(() => backdrop.classList.add('is-open'));
    springY.setImmediate(prefersReducedMotion() ? 0 : 32);
    applyTransform(springY.value);
    springY.animateTo(0, { onUpdate: applyTransform });
  }

  function close(releaseVelocity = 0) {
    if (!isOpen) return;
    isOpen = false;
    backdrop.classList.remove('is-open');

    if (prefersReducedMotion()) {
      backdrop.hidden = true;
      if (onCloseCallback) onCloseCallback();
      return;
    }

    springY.animateTo(220, {
      velocity: Math.max(releaseVelocity, 0),
      onUpdate: applyTransform,
      onRest: () => {
        if (!isOpen) {
          backdrop.hidden = true;
          if (onCloseCallback) onCloseCallback();
        }
      },
    });
  }

  dragHandle.addEventListener('pointerdown', (e) => {
    if (!isOpen) return;
    dragging = true;
    springY.stop();
    dragHandle.setPointerCapture(e.pointerId);
    startY = e.clientY;
    startOffset = springY.value;
    samples = [{ y: e.clientY, t: performance.now() }];
  });

  dragHandle.addEventListener('pointermove', (e) => {
    if (!dragging) return;
    const rawDelta = e.clientY - startY;
    const nextY = startOffset + rawDelta;
    // Progressive rubber-banding when pulling upward past resting position
    const clampedY = nextY < 0 ? rubberband(nextY, 240, 0.35) : nextY;
    springY.setImmediate(clampedY);
    applyTransform(clampedY);

    const now = performance.now();
    samples.push({ y: e.clientY, t: now });
    if (samples.length > 5) samples.shift();
  });

  const endDrag = () => {
    if (!dragging) return;
    dragging = false;

    let velocity = 0;
    if (samples.length >= 2) {
      const first = samples[0];
      const last = samples[samples.length - 1];
      const dtSec = Math.max((last.t - first.t) / 1000, 0.008);
      velocity = (last.y - first.y) / dtSec;
    }

    // Project resting endpoint from finger release velocity
    const projectedY = springY.value + projectMomentum(velocity, 0.99);
    if (projectedY > 110 || springY.value > 110) {
      close(velocity);
    } else {
      springY.animateTo(0, { velocity, onUpdate: applyTransform });
    }
  };

  dragHandle.addEventListener('pointerup', endDrag);
  dragHandle.addEventListener('pointercancel', endDrag);

  backdrop.addEventListener('click', (e) => {
    if (e.target === backdrop) close();
  });

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && isOpen) close();
  });

  return { open, close };
}
