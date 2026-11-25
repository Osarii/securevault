// Magic UI + 21st.dev Pointer Spotlight & Collapsible Glass Interactions
// Strictly external ES module (CSP-safe) and respects prefers-reduced-motion.

export function initMagicSpotlights() {
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const finePointer = window.matchMedia('(hover: hover) and (pointer: fine)').matches;
  if (reduced || !finePointer) return;

  const cards = document.querySelectorAll('[data-spotlight]');
  cards.forEach((card) => {
    card.addEventListener('pointermove', (e) => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      card.style.setProperty('--mx', `${x}px`);
      card.style.setProperty('--my', `${y}px`);
    });
  });
}

export function initSidebarCollapse() {
  const shell = document.querySelector('#app-shell');
  const toggleBtn = document.querySelector('#sidebar-collapse-btn');
  if (!shell || !toggleBtn) return;

  const saved = localStorage.getItem('sv_sidebar_collapsed') === '1';
  if (saved) shell.classList.add('is-collapsed');

  toggleBtn.addEventListener('click', () => {
    const collapsed = shell.classList.toggle('is-collapsed');
    localStorage.setItem('sv_sidebar_collapsed', collapsed ? '1' : '0');
    toggleBtn.setAttribute('aria-expanded', String(!collapsed));
  });
}
