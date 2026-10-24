const copyButton = document.querySelector('[data-copy]');
const copyStatus = document.getElementById('copy-status');

if (copyButton && copyStatus && navigator.clipboard) {
  copyButton.hidden = false;
  copyButton.addEventListener('click', async () => {
    const command = document.getElementById(copyButton.dataset.copy);
    if (!command) return;
    try {
      await navigator.clipboard.writeText(command.textContent.trim());
      copyStatus.textContent = 'Installation commands copied.';
    } catch {
      copyStatus.textContent = 'Copy is unavailable. Select the commands above and copy them manually.';
    }
  });
}
