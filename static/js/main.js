/* ESEAS — main.js */

document.addEventListener('DOMContentLoaded', () => {

  // ---- Auto-dismiss Bootstrap toasts after 4 s ----
  document.querySelectorAll('.toast').forEach(toastEl => {
    const toast = bootstrap.Toast.getOrCreateInstance(toastEl, { delay: 4000 });
    toast.show();
    toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
  });

  // ---- Animated stat counters (Intersection Observer) ----
  const counters = document.querySelectorAll('.stat-number[data-target]');

  if (counters.length === 0) return;

  const animate = (el) => {
    const target = parseInt(el.dataset.target, 10);
    const suffix = el.dataset.suffix || (target >= 100 ? '+' : '%');
    const duration = 1800;
    const step = Math.ceil(target / (duration / 16));
    let current = 0;

    const tick = () => {
      current = Math.min(current + step, target);
      el.textContent = current.toLocaleString() + suffix;
      if (current < target) requestAnimationFrame(tick);
    };

    requestAnimationFrame(tick);
  };

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting && !entry.target.dataset.animated) {
        entry.target.dataset.animated = '1';
        animate(entry.target);
      }
    });
  }, { threshold: 0.3 });

  counters.forEach(el => observer.observe(el));

});
