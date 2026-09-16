'use strict';
(async () => {
  const target = document.getElementById('status');
  try {
    const evidence = await window.atlas.status();
    target.textContent = JSON.stringify(evidence, null, 2);
  } catch (error) {
    target.textContent = `FAIL-CLOSED\n\n${String(error)}`;
  }
})();
