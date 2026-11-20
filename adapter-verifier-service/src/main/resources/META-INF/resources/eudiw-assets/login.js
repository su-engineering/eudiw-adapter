// The wallet login page of the eudiw-adapter OpenID Connect provider (ADR-018). The <eudiw-request> element shows
// the QR code and the wallet link and follows the login's status URL; when the login ends, the status carries the
// redirect back to the application, with the authorization code or an error.
const request = document.querySelector('eudiw-request');
request?.addEventListener('eudiw-done', (event) => {
  const redirect = event.detail?.response?.redirect;
  if (typeof redirect === 'string') {
    // A short pause so the final state is readable before the page changes.
    setTimeout(() => window.location.assign(redirect), event.detail.status === 'verified' ? 400 : 1500);
  }
});
